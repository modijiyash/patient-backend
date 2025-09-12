import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 10001;
const MONGO_URI = process.env.MONGODB_URI || "mongodb://127.0.0.1:27017/elderEase";
const JWT_SECRET = process.env.JWT_SECRET || "super_secret_key";
const CLIENT_URL = process.env.CLIENT_URL || "http://localhost:8090";

// Middleware
app.use(express.json());
app.use(
  cors({
    origin: [
      "http://localhost:8080",  // ✅ allow frontend running on 8080
      "http://localhost:8090",  // ✅ allow frontend running on 8090
      "https://patient-frontend-txxi.vercel.app" // ✅ deployed frontend
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

// Schemas
const PatientSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    age: { type: Number },
    gender: { type: String, enum: ["male", "female", "other"] },
    phone: { type: String, unique: true },
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
    patientId: { type: mongoose.Schema.Types.ObjectId, ref: "Patient", default: null },
    patientName: { type: String, required: true },
    doctor: { type: String, default: "Unassigned" },
    date: { type: String, required: true },
    time: { type: String, required: true },
    reason: { type: String, default: "" },
    status: { type: String, enum: ["pending", "confirmed", "completed", "cancelled"], default: "pending" },
  },
  { collection: "appointments", timestamps: true }
);

// Models
const Patient = mongoose.models.Patient || mongoose.model("Patient", PatientSchema);
const Appointment = mongoose.models.Appointment || mongoose.model("Appointment", AppointmentSchema);

// Auth Helpers
function parseAuthToken(req) {
  const authHeader = req.headers.authorization || req.headers["x-access-token"] || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : authHeader;
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
    if (!decoded) return res.status(403).json({ status: "error", message: "No token or invalid token" });
    if (roles.length && !roles.includes(decoded.role)) return res.status(403).json({ status: "error", message: "Access denied" });
    req.user = decoded;
    next();
  };
};

// Routes
app.get("/health", (_req, res) => res.json({ ok: true }));

app.post("/signup", async (req, res) => {
  try {
    const { name, email, password, confirmPassword, age, gender, phone } = req.body;

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

    const patient = await Patient.create({ name, email, password: hashed, age, gender, phone, status: "new" });

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
    if (!email || !password) return res.status(400).json({ status: "error", message: "Email and password required" });

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
        role: "patient",
      },
    });
  } catch (err) {
    console.error("❌ Login error:", err);
    res.status(500).json({ status: "error", message: "Server error" });
  }
});

app.get("/profile", authMiddleware(["patient"]), async (req, res) => {
  try {
    const patient = await Patient.findById(req.user.id).select("-password");
    if (!patient) return res.status(404).json({ status: "error", message: "Patient not found" });
    res.json({ status: "ok", user: patient });
  } catch (err) {
    res.status(500).json({ status: "error", message: "Server error" });
  }
});

app.get("/patients", authMiddleware(["doctor"]), async (_req, res) => {
  try {
    const patients = await Patient.find().select("-password");
    res.json({ status: "ok", patients });
  } catch (err) {
    res.status(500).json({ status: "error", message: "Server error" });
  }
});

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
    res.status(500).json({ status: "error", message: "Server error", error: err.message });
  }
}

app.get("/appointments", authMiddleware(["patient"]), async (req, res) => {
  try {
    const appointments = await Appointment.find({ patientId: req.user.id }).sort({ date: 1, time: 1 });
    res.json({ status: "ok", appointments });
  } catch (err) {
    res.status(500).json({ status: "error", message: "Server error" });
  }
});

app.get("/appointments/all", authMiddleware(["doctor"]), async (_req, res) => {
  try {
    const appointments = await Appointment.find().sort({ createdAt: -1 });
    res.json({ status: "ok", appointments });
  } catch (err) {
    res.status(500).json({ status: "error", message: "Server error" });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Patient API running on port ${PORT}`);
});
