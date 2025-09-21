import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import twilio from "twilio";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 10001;
const MONGO_URI =
  process.env.MONGODB_URI || "mongodb://127.0.0.1:27017/elderEase";
const JWT_SECRET = process.env.JWT_SECRET || "super_secret_key";

const twilioClient = twilio(process.env.TWILIO_SID, process.env.TWILIO_AUTH);

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

mongoose
  .connect(MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("✅ MongoDB connected"))
  .catch((err) => console.error("❌ MongoDB connection error:", err));

/* SCHEMAS */
const PatientSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    age: { type: Number },
    gender: { type: String, enum: ["male", "female", "other"] },
    phone: { type: String, unique: true },
    relativePhone: { type: String, default: "" },
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

const ReminderSchema = new mongoose.Schema(
  {
    patientId: { type: mongoose.Schema.Types.ObjectId, ref: "Patient", required: true },
    title: { type: String, required: true },
    description: { type: String, default: "" },
    date: { type: String, required: true },
    time: { type: String, required: true },
    completed: { type: Boolean, default: false },
  },
  { collection: "reminders", timestamps: true }
);

/* MODELS */
const Patient = mongoose.models.Patient || mongoose.model("Patient", PatientSchema);
const Appointment = mongoose.models.Appointment || mongoose.model("Appointment", AppointmentSchema);
const Geofence = mongoose.models.Geofence || mongoose.model("Geofence", GeofenceSchema);
const Alert = mongoose.models.Alert || mongoose.model("Alert", AlertSchema);
const Reminder = mongoose.models.Reminder || mongoose.model("Reminder", ReminderSchema);

/* HELPERS */
// ✅ Normalize phone numbers to E.164 (+91 default if missing)
function formatPhone(num) {
  if (!num) return "";
  return num.startsWith("+") ? num : `+91${num}`;
}

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

/* ROUTES */
app.get("/health", (_req, res) => res.json({ ok: true }));

/* AUTH */
app.post("/signup", async (req, res) => {
  try {
    let { name, email, password, confirmPassword, age, gender, phone, relativePhone } = req.body;

    if (!name || !email || !password || !confirmPassword || !age || !gender || !phone)
      return res.status(400).json({ status: "error", message: "All fields required" });

    if (password !== confirmPassword)
      return res.status(400).json({ status: "error", message: "Passwords do not match" });

    if (password.length < 6)
      return res.status(400).json({ status: "error", message: "Password must be at least 6 characters" });

    // ✅ normalize phone
    phone = formatPhone(phone);
    relativePhone = formatPhone(relativePhone);

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
      relativePhone,
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
    let { email, password } = req.body;
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

/* PROFILE */
app.get("/profile", authMiddleware(["patient"]), async (req, res) => {
  try {
    const patient = await Patient.findById(req.user.id).select("-password");
    if (!patient) return res.status(404).json({ status: "error", message: "Patient not found" });
    res.json({ status: "ok", user: patient });
  } catch {
    res.status(500).json({ status: "error", message: "Server error" });
  }
});

/* GEOFENCE + ALERTS + REMINDERS remain unchanged, only signup/login had fixes */

/* TWILIO ALERTS */
app.post("/api/alerts/send-sms", authMiddleware(["patient"]), async (req, res) => {
  try {
    const patient = await Patient.findById(req.user.id);
    if (!patient?.relativePhone) {
      return res.status(400).json({ status: "error", message: "Relative phone not set" });
    }

    const toPhone = formatPhone(patient.relativePhone);

    const message = await twilioClient.messages.create({
      body: `🚨 Alert: ${patient.name} is outside the designated safe zone. Please check on them immediately.`,
      from: process.env.TWILIO_PHONE,
      to: toPhone,
    });

    res.json({ status: "ok", sid: message.sid });
  } catch (err) {
    console.error("❌ SMS Error:", err);
    res.status(500).json({ status: "error", message: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
