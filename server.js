import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import twilio from "twilio"; // ✅ Twilio added

dotenv.config();

const app = express();
const PORT = process.env.PORT || 10001;
const MONGO_URI =
  process.env.MONGODB_URI || "mongodb://127.0.0.1:27017/elderEase";
const JWT_SECRET = process.env.JWT_SECRET || "super_secret_key";

// ✅ Twilio client
const twilioClient = twilio(process.env.TWILIO_SID, process.env.TWILIO_AUTH);

// Middleware
app.use(express.json());
app.use(
  cors({
    origin: [
      "http://localhost:8080",
      "http://localhost:8090",
      "https://patient-frontend-txxi.vercel.app",
    ],
    credentials: true,
  })
);

// MongoDB Connection
mongoose
  .connect(MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("✅ MongoDB connected"))
  .catch((err) => console.error("❌ MongoDB connection error:", err));

/* ================================
   SCHEMAS & MODELS
================================ */
const PatientSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    age: { type: Number },
    gender: { type: String, enum: ["male", "female", "other"] },
    phone: { type: String, unique: true },
    relativePhone: { type: String, default: "" }, // ✅ NEW FIELD
    condition: { type: String, default: "" },
    ongoingTreatment: { type: String, default: "" },
    lastVisit: { type: Date, default: null },
    status: {
      type: String,
      enum: ["critical", "attention", "stable", "new"],
      default: "new",
    },
  },
  { collection: "patients" }
);

const AppointmentSchema = new mongoose.Schema(
  {
    patientId: { type: mongoose.Schema.Types.ObjectId, ref: "Patient" },
    patientName: { type: String, required: true },
    doctor: { type: String, default: "Unassigned" },
    date: { type: String, required: true },
    time: { type: String, required: true },
    reason: { type: String, default: "" },
    status: {
      type: String,
      enum: ["pending", "confirmed", "completed", "cancelled"],
      default: "pending",
    },
  },
  { collection: "appointments", timestamps: true }
);

const GeofenceSchema = new mongoose.Schema(
  {
    patientId: { type: mongoose.Schema.Types.ObjectId, ref: "Patient", required: true },
    geofence: { lat: Number, lng: Number },
    currentLocation: { lat: Number, lng: Number },
    createdAt: { type: Date, default: Date.now },
  },
  { collection: "geofences" }
);

const AlertSchema = new mongoose.Schema(
  {
    patientId: { type: mongoose.Schema.Types.ObjectId, ref: "Patient", required: true },
    type: { type: String, enum: ["geofence", "sos"], required: true },
    message: { type: String, required: true },
    createdAt: { type: Date, default: Date.now },
  },
  { collection: "alerts" }
);

// Models
const Patient =
  mongoose.models.Patient || mongoose.model("Patient", PatientSchema);
const Appointment =
  mongoose.models.Appointment || mongoose.model("Appointment", AppointmentSchema);
const Geofence =
  mongoose.models.Geofence || mongoose.model("Geofence", GeofenceSchema);
const Alert =
  mongoose.models.Alert || mongoose.model("Alert", AlertSchema);

/* ================================
   AUTH HELPERS
================================ */
function parseAuthToken(req) {
  const authHeader =
    req.headers.authorization || req.headers["x-access-token"] || "";
  const token = authHeader.startsWith("Bearer ")
    ? authHeader.slice(7)
    : authHeader;
  if (!token) return null;
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch {
    return null;
  }
}

const authMiddleware = (roles = []) => {
  return (req, res, next) => {
    const decoded = parseAuthToken(req);
    if (!decoded)
      return res
        .status(403)
        .json({ status: "error", message: "No token or invalid token" });
    if (roles.length && !roles.includes(decoded.role))
      return res
        .status(403)
        .json({ status: "error", message: "Access denied" });
    req.user = decoded;
    next();
  };
};

/* ================================
   ROUTES
================================ */
app.get("/health", (_req, res) => res.json({ ok: true }));

/* ---------- AUTH ---------- */
app.post("/signup", async (req, res) => {
  try {
    const { name, email, password, confirmPassword, age, gender, phone, relativePhone } = req.body;

    if (!name || !email || !password || !confirmPassword || !age || !gender || !phone)
      return res.status(400).json({ status: "error", message: "All fields required" });

    if (password !== confirmPassword)
      return res.status(400).json({ status: "error", message: "Passwords do not match" });

    if (password.length < 6)
      return res.status(400).json({ status: "error", message: "Password must be at least 6 characters" });

    if (!/^\d{10}$/.test(phone))
      return res.status(400).json({ status: "error", message: "Invalid phone number" });

    const existing = await Patient.findOne({ $or: [{ email }, { phone }] });
    if (existing)
      return res.status(400).json({ status: "error", message: "User with this email or phone exists" });

    const hashed = await bcrypt.hash(password, 10);

    const patient = await Patient.create({
      name,
      email,
      password: hashed,
      age,
      gender,
      phone,
      relativePhone, // ✅ store relative phone
      status: "new",
    });

    res.json({
      status: "ok",
      message: "Registered successfully",
      user: {
        id: patient._id,
        name: patient.name,
        email: patient.email,
        age: patient.age,
        gender: patient.gender,
        phone: patient.phone,
        relativePhone: patient.relativePhone,
        role: "patient",
      },
    });
  } catch (err) {
    console.error("❌ Signup error:", err);
    res.status(500).json({ status: "error", message: "Server error" });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ status: "error", message: "Email and password required" });

    const patient = await Patient.findOne({ email });
    if (!patient) return res.status(404).json({ status: "error", message: "Patient not found" });

    const ok = await bcrypt.compare(password, patient.password);
    if (!ok) return res.status(401).json({ status: "error", message: "Invalid password" });

    const token = jwt.sign({ id: patient._id, name: patient.name, role: "patient" }, JWT_SECRET, { expiresIn: "1h" });

    res.json({
      status: "ok",
      token,
      user: {
        id: patient._id,
        name: patient.name,
        email: patient.email,
        age: patient.age,
        gender: patient.gender,
        phone: patient.phone,
        relativePhone: patient.relativePhone,
        role: "patient",
      },
    });
  } catch (err) {
    console.error("❌ Login error:", err);
    res.status(500).json({ status: "error", message: "Server error" });
  }
});

/* ---------- PROFILE ---------- */
app.get("/profile", authMiddleware(["patient"]), async (req, res) => {
  try {
    const patient = await Patient.findById(req.user.id).select("-password");
    if (!patient) return res.status(404).json({ status: "error", message: "Patient not found" });
    res.json({ status: "ok", user: patient });
  } catch {
    res.status(500).json({ status: "error", message: "Server error" });
  }
});

/* ---------- APPOINTMENTS ---------- */
app.post("/appointments", async (req, res) => handleCreateAppointment(req, res));
app.post("/api/appointments", async (req, res) => handleCreateAppointment(req, res));

async function handleCreateAppointment(req, res) {
  try {
    const decoded = parseAuthToken(req);
    const { doctor, date, time, reason, username, patientName } = req.body;

    if (!date || !time)
      return res.status(400).json({ status: "error", message: "Date and time required" });

    const finalPatientName = patientName || username || (decoded?.name ?? null);
    const patientId = decoded?.id ?? null;

    if (!finalPatientName)
      return res.status(400).json({ status: "error", message: "Patient name is required" });

    const appointment = await Appointment.create({
      patientId,
      patientName: finalPatientName,
      doctor: doctor || "Unassigned",
      date,
      time,
      reason: reason || "",
    });

    res.json({ status: "ok", message: "Appointment booked", appointment });
  } catch (err) {
    res.status(500).json({ status: "error", message: err.message });
  }
}

/* ---------- GEOFENCE ---------- */
app.post("/api/geofence/set", authMiddleware(["patient"]), async (req, res) => {
  try {
    const { lat, lng } = req.body;
    const patientId = req.user.id;

    if (!lat || !lng)
      return res.status(400).json({ status: "error", message: "Lat/Lng required" });

    const geofence = await Geofence.findOneAndUpdate(
      { patientId },
      { geofence: { lat, lng } },
      { new: true, upsert: true }
    );

    res.json({ status: "ok", message: "Geofence set", geofence });
  } catch (err) {
    res.status(500).json({ status: "error", message: err.message });
  }
});

app.post("/api/geofence/update-location", authMiddleware(["patient"]), async (req, res) => {
  try {
    const { lat, lng } = req.body;
    const patientId = req.user.id;

    if (!lat || !lng)
      return res.status(400).json({ status: "error", message: "Lat/Lng required" });

    const geofenceData = await Geofence.findOneAndUpdate(
      { patientId },
      { currentLocation: { lat, lng } },
      { new: true, upsert: true }
    );

    if (!geofenceData?.geofence) {
      return res.json({ status: "ok", message: "No geofence set yet" });
    }

    const { geofence } = geofenceData;

    const withinGeofence =
      Math.abs(lat - geofence.lat) < 0.01 &&
      Math.abs(lng - geofence.lng) < 0.01;

    if (!withinGeofence) {
      // Save alert in DB
      await Alert.create({
        patientId,
        type: "geofence",
        message: "⚠ Patient has left the geofenced area!",
      });
    }

    res.json({ status: "ok", withinGeofence, geofence: geofenceData.geofence });
  } catch (err) {
    res.status(500).json({ status: "error", message: err.message });
  }
});

/* ---------- ALERTS ---------- */
app.get("/api/alerts", authMiddleware(["patient", "doctor"]), async (req, res) => {
  try {
    const query = req.user.role === "patient" ? { patientId: req.user.id } : {};
    const alerts = await Alert.find(query).sort({ createdAt: -1 }).populate("patientId", "name email phone relativePhone");
    res.json({ status: "ok", alerts });
  } catch (err) {
    res.status(500).json({ status: "error", message: err.message });
  }
});

/* ---------- TWILIO ALERTS ---------- */
app.post("/api/alerts/send-sms", authMiddleware(["patient"]), async (req, res) => {
  try {
    const patient = await Patient.findById(req.user.id);
    if (!patient?.relativePhone) {
      return res.status(400).json({ status: "error", message: "Relative phone not set" });
    }

    const { hospitalName = "Unknown Hospital" } = req.body;

    const message = await twilioClient.messages.create({
      body: `🚨 Emergency Alert: ${patient.name} is unresponsive at ${hospitalName}. Please respond immediately.`,
      from: process.env.TWILIO_PHONE,
      to: patient.relativePhone,
    });

    res.json({ status: "ok", sid: message.sid });
  } catch (err) {
    console.error("❌ SMS Error:", err);
    res.status(500).json({ status: "error", message: err.message });
  }
});

app.post("/api/alerts/make-call", authMiddleware(["patient"]), async (req, res) => {
  try {
    const patient = await Patient.findById(req.user.id);
    if (!patient?.relativePhone) {
      return res.status(400).json({ status: "error", message: "Relative phone not set" });
    }

    const call = await twilioClient.calls.create({
      twiml: "<Response><Say>🚨 Emergency Alert. Please check your patient immediately.</Say></Response>",
      from: process.env.TWILIO_PHONE,
      to: patient.relativePhone,
    });

    res.json({ status: "ok", sid: call.sid });
  } catch (err) {
    console.error("❌ Call Error:", err);
    res.status(500).json({ status: "error", message: err.message });
  }
});

/* ================================
   START SERVER
================================ */
app.listen(PORT, () => {
  console.log(`🚀 Patient API running on port ${PORT}`);
});
