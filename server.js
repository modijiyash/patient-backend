import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import twilio from "twilio";
import { OAuth2Client } from "google-auth-library";

dotenv.config();

/* =========================================================
   APP CONFIGURATION
========================================================= */

const app = express();

const PORT = process.env.PORT || 10001;

const MONGO_URI =
  process.env.MONGODB_URI ||
  "mongodb://127.0.0.1:27017/elderEase";

const JWT_SECRET =
  process.env.JWT_SECRET || "super_secret_key";

const GOOGLE_CLIENT_ID =
  process.env.GOOGLE_CLIENT_ID || "";

/*
  Google OAuth client.
  Used by the backend to verify Google's ID token.
*/
const googleClient =
  new OAuth2Client(GOOGLE_CLIENT_ID);

/*
  Twilio client
*/
const twilioClient = twilio(
  process.env.TWILIO_SID,
  process.env.TWILIO_AUTH
);

/* =========================================================
   MIDDLEWARE
========================================================= */

app.use(express.json());

app.use(
  cors({
    origin: [
      "http://localhost:5173",
      "http://localhost:8080",
      "http://localhost:8090",
      "https://patient-frontend-txxi.vercel.app",
    ],
    credentials: true,
  })
);

/* =========================================================
   DATABASE
========================================================= */

mongoose
  .connect(MONGO_URI)
  .then(() => {
    console.log("✅ MongoDB connected");
  })
  .catch((err) => {
    console.error(
      "❌ MongoDB connection error:",
      err
    );
  });

/* =========================================================
   PATIENT SCHEMA
========================================================= */

const PatientSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
    },

    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
    },

    /*
      Local password is optional because
      Google users do not have a local password.
    */
    password: {
      type: String,
      required: false,
      default: "",
    },

    /*
      Google authentication
    */
    googleId: {
      type: String,
      unique: true,
      sparse: true,
    },

    authProvider: {
      type: String,
      enum: ["local", "google"],
      default: "local",
    },

    age: {
      type: Number,
    },

    gender: {
      type: String,
      enum: ["male", "female", "other"],
    },

    phone: {
      type: String,
      unique: true,
      sparse: true,
    },

    relativePhone: {
      type: String,
      default: "",
    },

    condition: {
      type: String,
      default: "",
    },

    ongoingTreatment: {
      type: String,
      default: "",
    },

    lastVisit: {
      type: Date,
      default: null,
    },

    status: {
      type: String,
      enum: [
        "critical",
        "attention",
        "stable",
        "new",
      ],
      default: "new",
    },
  },
  {
    collection: "patients",
  }
);

/* =========================================================
   APPOINTMENT SCHEMA
========================================================= */

const AppointmentSchema = new mongoose.Schema(
  {
    patientId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Patient",
    },

    patientName: {
      type: String,
      required: true,
    },

    doctor: {
      type: String,
      default: "Unassigned",
    },

    date: {
      type: String,
      required: true,
    },

    time: {
      type: String,
      required: true,
    },

    reason: {
      type: String,
      default: "",
    },

    status: {
      type: String,
      enum: [
        "pending",
        "confirmed",
        "completed",
        "cancelled",
      ],
      default: "pending",
    },
  },
  {
    collection: "appointments",
    timestamps: true,
  }
);

/* =========================================================
   GEOFENCE SCHEMA
========================================================= */

const GeofenceSchema = new mongoose.Schema(
  {
    patientId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Patient",
      required: true,
    },

    geofence: {
      lat: Number,
      lng: Number,
    },

    currentLocation: {
      lat: Number,
      lng: Number,
    },

    createdAt: {
      type: Date,
      default: Date.now,
    },
  },
  {
    collection: "geofences",
  }
);

/* =========================================================
   ALERT SCHEMA
========================================================= */

const AlertSchema = new mongoose.Schema(
  {
    patientId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Patient",
      required: true,
    },

    type: {
      type: String,
      enum: ["geofence", "sos"],
      required: true,
    },

    message: {
      type: String,
      required: true,
    },

    createdAt: {
      type: Date,
      default: Date.now,
    },
  },
  {
    collection: "alerts",
  }
);

/* =========================================================
   REMINDER SCHEMA
========================================================= */

const ReminderSchema = new mongoose.Schema(
  {
    patientId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Patient",
      required: true,
    },

    title: {
      type: String,
      required: true,
    },

    description: {
      type: String,
      default: "",
    },

    date: {
      type: String,
      required: true,
    },

    time: {
      type: String,
      required: true,
    },

    completed: {
      type: Boolean,
      default: false,
    },
  },
  {
    collection: "reminders",
    timestamps: true,
  }
);

/* =========================================================
   MODELS
========================================================= */

const Patient =
  mongoose.models.Patient ||
  mongoose.model(
    "Patient",
    PatientSchema
  );

const Appointment =
  mongoose.models.Appointment ||
  mongoose.model(
    "Appointment",
    AppointmentSchema
  );

const Geofence =
  mongoose.models.Geofence ||
  mongoose.model(
    "Geofence",
    GeofenceSchema
  );

const Alert =
  mongoose.models.Alert ||
  mongoose.model(
    "Alert",
    AlertSchema
  );

const Reminder =
  mongoose.models.Reminder ||
  mongoose.model(
    "Reminder",
    ReminderSchema
  );

/* =========================================================
   AUTH HELPERS
========================================================= */

function parseAuthToken(req) {
  const authHeader =
    req.headers.authorization ||
    req.headers["x-access-token"] ||
    "";

  const token =
    authHeader.startsWith("Bearer ")
      ? authHeader.slice(7)
      : authHeader;

  if (!token) {
    return null;
  }

  try {
    return jwt.verify(
      token,
      JWT_SECRET
    );
  } catch {
    return null;
  }
}

/* =========================================================
   AUTH MIDDLEWARE
========================================================= */

const authMiddleware = (roles = []) => {
  return (req, res, next) => {
    const decoded =
      parseAuthToken(req);

    if (!decoded) {
      return res.status(403).json({
        status: "error",
        message:
          "No token or invalid token",
      });
    }

    if (
      roles.length &&
      !roles.includes(decoded.role)
    ) {
      return res.status(403).json({
        status: "error",
        message: "Access denied",
      });
    }

    req.user = decoded;

    next();
  };
};

/* =========================================================
   HEALTH CHECK
========================================================= */

app.get("/health", (_req, res) => {
  res.json({
    ok: true,
    googleLoginConfigured:
      Boolean(GOOGLE_CLIENT_ID),
  });
});

/* =========================================================
   NORMAL SIGNUP
========================================================= */

app.post("/signup", async (req, res) => {
  try {
    const {
      name,
      email,
      password,
      confirmPassword,
      age,
      gender,
      phone,
      relativePhone,
    } = req.body;

    if (
      !name ||
      !email ||
      !password ||
      !confirmPassword ||
      !age ||
      !gender ||
      !phone
    ) {
      return res.status(400).json({
        status: "error",
        message: "All fields required",
      });
    }

    if (password !== confirmPassword) {
      return res.status(400).json({
        status: "error",
        message:
          "Passwords do not match",
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        status: "error",
        message:
          "Password must be at least 6 characters",
      });
    }

    const normalizedEmail =
      email.toLowerCase().trim();

    const existing =
      await Patient.findOne({
        $or: [
          {
            email: normalizedEmail,
          },
          {
            phone,
          },
        ],
      });

    if (existing) {
      return res.status(400).json({
        status: "error",
        message:
          "User with this email or phone exists",
      });
    }

    const hashed =
      await bcrypt.hash(
        password,
        10
      );

    const patient =
      await Patient.create({
        name,
        email: normalizedEmail,
        password: hashed,
        age: Number(age),
        gender,
        phone,
        relativePhone:
          relativePhone || "",
        authProvider: "local",
        status: "new",
      });

    return res.json({
      status: "ok",
      message:
        "Registered successfully",

      user: {
        id: patient._id,
        name: patient.name,
        email: patient.email,
        age: patient.age,
        gender: patient.gender,
        phone: patient.phone,
        relativePhone:
          patient.relativePhone,
        role: "patient",
      },
    });
  } catch (err) {
    console.error(
      "❌ Signup error:",
      err
    );

    return res.status(500).json({
      status: "error",
      message: "Server error",
    });
  }
});

/* =========================================================
   NORMAL LOGIN
========================================================= */

app.post("/login", async (req, res) => {
  try {
    const {
      email,
      password,
    } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        status: "error",
        message:
          "Email and password required",
      });
    }

    const normalizedEmail =
      email.toLowerCase().trim();

    const patient =
      await Patient.findOne({
        email: normalizedEmail,
      });

    if (!patient) {
      return res.status(404).json({
        status: "error",
        message:
          "Patient not found",
      });
    }

    /*
      Google-only users don't have
      a local password.
    */
    if (
      !patient.password ||
      patient.authProvider === "google"
    ) {
      return res.status(401).json({
        status: "error",
        message:
          "This account uses Google Login. Please continue with Google.",
      });
    }

    const ok =
      await bcrypt.compare(
        password,
        patient.password
      );

    if (!ok) {
      return res.status(401).json({
        status: "error",
        message:
          "Invalid password",
      });
    }

    const token =
      jwt.sign(
        {
          id: patient._id,
          name: patient.name,
          role: "patient",
        },
        JWT_SECRET,
        {
          expiresIn: "1h",
        }
      );

    return res.json({
      status: "ok",
      token,

      user: {
        id: patient._id,
        name: patient.name,
        email: patient.email,
        age: patient.age,
        gender: patient.gender,
        phone: patient.phone,
        relativePhone:
          patient.relativePhone,
        role: "patient",
      },
    });
  } catch (err) {
    console.error(
      "❌ Login error:",
      err
    );

    return res.status(500).json({
      status: "error",
      message: "Server error",
    });
  }
});

/* =========================================================
   GOOGLE LOGIN
========================================================= */

app.post(
  "/google-login",
  async (req, res) => {
    try {
      const { credential } =
        req.body;

      if (!credential) {
        return res.status(400).json({
          status: "error",
          message:
            "Google credential is required",
        });
      }

      if (!GOOGLE_CLIENT_ID) {
        console.error(
          "❌ GOOGLE_CLIENT_ID is not configured"
        );

        return res.status(500).json({
          status: "error",
          message:
            "Google login is not configured on the server",
        });
      }

      /*
        Verify the Google ID token.
      */
      const ticket =
        await googleClient.verifyIdToken({
          idToken: credential,
          audience:
            GOOGLE_CLIENT_ID,
        });

      const payload =
        ticket.getPayload();

      if (!payload) {
        return res.status(401).json({
          status: "error",
          message:
            "Invalid Google token",
        });
      }

      const {
        sub: googleId,
        email,
        email_verified,
        name,
        picture,
      } = payload;

      if (!googleId || !email) {
        return res.status(401).json({
          status: "error",
          message:
            "Google account information is incomplete",
        });
      }

      /*
        Make sure Google's email is verified.
      */
      if (!email_verified) {
        return res.status(401).json({
          status: "error",
          message:
            "Google email is not verified",
        });
      }

      const normalizedEmail =
        email.toLowerCase().trim();

      const googleName =
        name ||
        normalizedEmail.split("@")[0];

      /*
        First search by Google ID.
      */
      let patient =
        await Patient.findOne({
          googleId,
        });

      /*
        If Google ID isn't linked,
        search by email.
      */
      if (!patient) {
        patient =
          await Patient.findOne({
            email:
              normalizedEmail,
          });
      }

      /* =====================================================
         EXISTING USER
      ===================================================== */

      if (patient) {
        /*
          Prevent a different Google account
          from taking over an existing account.
        */
        if (
          patient.googleId &&
          patient.googleId !== googleId
        ) {
          return res.status(409).json({
            status: "error",
            message:
              "This email is already linked to another Google account",
          });
        }

        /*
          Link Google account.
        */
        patient.googleId =
          googleId;

        patient.authProvider =
          "google";

        await patient.save();

        /*
          Create Neuro-Aid JWT.
        */
        const token =
          jwt.sign(
            {
              id: patient._id,
              name: patient.name,
              role: "patient",
            },
            JWT_SECRET,
            {
              expiresIn: "1h",
            }
          );

        /*
          Check whether profile is complete.
        */
        const requiresProfile =
          !patient.age ||
          !patient.gender ||
          !patient.phone ||
          !patient.relativePhone;

        return res.json({
          status: "ok",
          token,
          requiresProfile,

          user: {
            id: patient._id,
            name: patient.name,
            email: patient.email,
            age: patient.age,
            gender: patient.gender,
            phone: patient.phone,
            relativePhone:
              patient.relativePhone,
            role: "patient",
          },
        });
      }

      /* =====================================================
         NEW GOOGLE USER
      ===================================================== */

      return res.json({
        status: "ok",

        requiresProfile: true,

        googleProfile: {
          googleId,
          name: googleName,
          email: normalizedEmail,
          picture:
            picture || "",
        },

        message:
          "Complete your patient profile to finish signup",
      });
    } catch (err) {
      console.error(
        "❌ Google login error:",
        err
      );

      return res.status(401).json({
        status: "error",
        message:
          "Google authentication failed",
      });
    }
  }
);

/* =========================================================
   GOOGLE COMPLETE PROFILE
========================================================= */

app.post(
  "/google-complete-profile",
  async (req, res) => {
    try {
      const {
        googleId,
        name,
        email,
        age,
        gender,
        phone,
        relativePhone,
      } = req.body;

      if (
        !googleId ||
        !name ||
        !email ||
        !age ||
        !gender ||
        !phone
      ) {
        return res.status(400).json({
          status: "error",
          message:
            "Name, email, age, gender and phone are required",
        });
      }

      const normalizedEmail =
        email.toLowerCase().trim();

      /*
        Check whether this Google account
        already exists.
      */
      let patient =
        await Patient.findOne({
          googleId,
        });

      /*
        Also check email.
      */
      if (!patient) {
        patient =
          await Patient.findOne({
            email:
              normalizedEmail,
          });
      }

      /* =====================================================
         EXISTING PATIENT
      ===================================================== */

      if (patient) {
        /*
          Prevent another Google account
          from taking over an account.
        */
        if (
          patient.googleId &&
          patient.googleId !== googleId
        ) {
          return res.status(409).json({
            status: "error",
            message:
              "This email is already connected to another Google account",
          });
        }

        patient.name = name;
        patient.email =
          normalizedEmail;
        patient.age = Number(age);
        patient.gender = gender;
        patient.phone = phone;
        patient.relativePhone =
          relativePhone || "";

        patient.googleId =
          googleId;

        patient.authProvider =
          "google";

        await patient.save();
      }

      /* =====================================================
         CREATE NEW GOOGLE PATIENT
      ===================================================== */

      else {
        patient =
          await Patient.create({
            name,

            email:
              normalizedEmail,

            /*
              Google accounts don't use
              a local password.
            */
            password: "",

            age: Number(age),

            gender,

            phone,

            relativePhone:
              relativePhone || "",

            googleId,

            authProvider:
              "google",

            status: "new",
          });
      }

      /*
        Create Neuro-Aid JWT.
      */
      const token =
        jwt.sign(
          {
            id: patient._id,
            name: patient.name,
            role: "patient",
          },
          JWT_SECRET,
          {
            expiresIn: "1h",
          }
        );

      return res.json({
        status: "ok",
        token,

        user: {
          id: patient._id,
          name: patient.name,
          email: patient.email,
          age: patient.age,
          gender: patient.gender,
          phone: patient.phone,
          relativePhone:
            patient.relativePhone,
          role: "patient",
        },
      });
    } catch (err) {
      console.error(
        "❌ Google profile completion error:",
        err
      );

      /*
        Mongo duplicate key error.
      */
      if (err?.code === 11000) {
        return res.status(400).json({
          status: "error",
          message:
            "An account with this email or phone already exists",
        });
      }

      return res.status(500).json({
        status: "error",
        message:
          "Could not complete Google signup",
      });
    }
  }
);

/* =========================================================
   PROFILE
========================================================= */

app.get(
  "/profile",
  authMiddleware(["patient"]),
  async (req, res) => {
    try {
      const patient =
        await Patient.findById(
          req.user.id
        ).select("-password");

      if (!patient) {
        return res.status(404).json({
          status: "error",
          message:
            "Patient not found",
        });
      }

      return res.json({
        status: "ok",
        user: patient,
      });
    } catch (err) {
      console.error(
        "❌ Profile error:",
        err
      );

      return res.status(500).json({
        status: "error",
        message: "Server error",
      });
    }
  }
);

/* =========================================================
   APPOINTMENTS
========================================================= */

app.post(
  "/appointments",
  async (req, res) =>
    handleCreateAppointment(
      req,
      res
    )
);

app.post(
  "/api/appointments",
  async (req, res) =>
    handleCreateAppointment(
      req,
      res
    )
);

async function handleCreateAppointment(
  req,
  res
) {
  try {
    const decoded =
      parseAuthToken(req);

    const {
      doctor,
      date,
      time,
      reason,
      username,
      patientName,
    } = req.body;

    if (!date || !time) {
      return res.status(400).json({
        status: "error",
        message:
          "Date and time required",
      });
    }

    const finalPatientName =
      patientName ||
      username ||
      decoded?.name ||
      null;

    const patientId =
      decoded?.id || null;

    if (!finalPatientName) {
      return res.status(400).json({
        status: "error",
        message:
          "Patient name is required",
      });
    }

    const appointment =
      await Appointment.create({
        patientId,

        patientName:
          finalPatientName,

        doctor:
          doctor || "Unassigned",

        date,

        time,

        reason:
          reason || "",
      });

    return res.json({
      status: "ok",
      message:
        "Appointment booked",
      appointment,
    });
  } catch (err) {
    console.error(
      "❌ Appointment error:",
      err
    );

    return res.status(500).json({
      status: "error",
      message: err.message,
    });
  }
}

/* =========================================================
   GEOFENCE - SET
========================================================= */

app.post(
  "/api/geofence/set",
  authMiddleware(["patient"]),
  async (req, res) => {
    try {
      const {
        lat,
        lng,
      } = req.body;

      const patientId =
        req.user.id;

      if (
        lat === undefined ||
        lng === undefined
      ) {
        return res.status(400).json({
          status: "error",
          message:
            "Lat/Lng required",
        });
      }

      const geofence =
        await Geofence.findOneAndUpdate(
          {
            patientId,
          },
          {
            geofence: {
              lat,
              lng,
            },
          },
          {
            new: true,
            upsert: true,
          }
        );

      return res.json({
        status: "ok",
        message:
          "Geofence set",
        geofence,
      });
    } catch (err) {
      console.error(
        "❌ Set geofence error:",
        err
      );

      return res.status(500).json({
        status: "error",
        message: err.message,
      });
    }
  }
);

/* =========================================================
   GEOFENCE - GET
========================================================= */

app.get(
  "/api/geofence/get",
  authMiddleware(["patient"]),
  async (req, res) => {
    try {
      const patientId =
        req.user.id;

      const geofenceData =
        await Geofence.findOne({
          patientId,
        });

      if (!geofenceData) {
        return res.json({
          status: "ok",
          geofence: null,
        });
      }

      return res.json({
        status: "ok",
        geofence:
          geofenceData.geofence,
      });
    } catch (err) {
      console.error(
        "❌ Get geofence error:",
        err
      );

      return res.status(500).json({
        status: "error",
        message: err.message,
      });
    }
  }
);

/* =========================================================
   GEOFENCE - UPDATE LOCATION
========================================================= */

app.post(
  "/api/geofence/update-location",
  authMiddleware(["patient"]),
  async (req, res) => {
    try {
      const {
        lat,
        lng,
      } = req.body;

      const patientId =
        req.user.id;

      if (
        lat === undefined ||
        lng === undefined
      ) {
        return res.status(400).json({
          status: "error",
          message:
            "Lat/Lng required",
        });
      }

      const geofenceData =
        await Geofence.findOneAndUpdate(
          {
            patientId,
          },
          {
            currentLocation: {
              lat,
              lng,
            },
          },
          {
            new: true,
            upsert: true,
          }
        );

      if (!geofenceData?.geofence) {
        return res.json({
          status: "ok",
          message:
            "No geofence set yet",
        });
      }

      const {
        geofence,
      } = geofenceData;

      /*
        Current simple geofence calculation.
      */
      const withinGeofence =
        Math.abs(
          lat - geofence.lat
        ) < 0.01 &&
        Math.abs(
          lng - geofence.lng
        ) < 0.01;

      /*
        Create alert if patient
        leaves the geofence.
      */
      if (!withinGeofence) {
        await Alert.create({
          patientId,

          type: "geofence",

          message:
            "⚠ Patient has left the geofenced area!",
        });
      }

      return res.json({
        status: "ok",
        withinGeofence,

        geofence:
          geofenceData.geofence,
      });
    } catch (err) {
      console.error(
        "❌ Update location error:",
        err
      );

      return res.status(500).json({
        status: "error",
        message: err.message,
      });
    }
  }
);

/* =========================================================
   ALERTS
========================================================= */

app.get(
  "/api/alerts",
  authMiddleware([
    "patient",
    "doctor",
  ]),
  async (req, res) => {
    try {
      const query =
        req.user.role ===
        "patient"
          ? {
              patientId:
                req.user.id,
            }
          : {};

      const alerts =
        await Alert.find(query)
          .sort({
            createdAt: -1,
          })
          .populate(
            "patientId",
            "name email phone relativePhone"
          );

      return res.json({
        status: "ok",
        alerts,
      });
    } catch (err) {
      console.error(
        "❌ Alerts error:",
        err
      );

      return res.status(500).json({
        status: "error",
        message: err.message,
      });
    }
  }
);

/* =========================================================
   TWILIO ALERTS
========================================================= */

app.post(
  "/api/alerts/send-sms",
  authMiddleware(["patient"]),
  async (req, res) => {
    try {
      const patient =
        await Patient.findById(
          req.user.id
        );

      if (
        !patient?.relativePhone
      ) {
        return res.status(400).json({
          status: "error",
          message:
            "Relative phone not set",
        });
      }

      if (
        !process.env.TWILIO_SID ||
        !process.env.TWILIO_AUTH ||
        !process.env.TWILIO_PHONE
      ) {
        return res.status(500).json({
          status: "error",
          message:
            "Twilio is not configured",
        });
      }

      const message =
        await twilioClient.messages.create(
          {
            body: `🚨 Alert: ${patient.name} is outside the designated safe zone. Please check on them immediately.`,

            from:
              process.env
                .TWILIO_PHONE,

            to:
              patient.relativePhone,
          }
        );

      return res.json({
        status: "ok",
        sid: message.sid,
      });
    } catch (err) {
      console.error(
        "❌ SMS Error:",
        err
      );

      return res.status(500).json({
        status: "error",
        message: err.message,
      });
    }
  }
);

/* =========================================================
   REMINDERS - CREATE
========================================================= */

app.post(
  "/api/reminders",
  authMiddleware(["patient"]),
  async (req, res) => {
    try {
      const {
        title,
        description,
        date,
        time,
      } = req.body;

      if (
        !title ||
        !date ||
        !time
      ) {
        return res.status(400).json({
          status: "error",
          message:
            "Title, date and time required",
        });
      }

      const reminder =
        await Reminder.create({
          patientId:
            req.user.id,

          title,

          description:
            description || "",

          date,

          time,

          completed: false,
        });

      return res.json({
        status: "ok",
        reminder,
      });
    } catch (err) {
      console.error(
        "❌ Create reminder error:",
        err
      );

      return res.status(500).json({
        status: "error",
        message: err.message,
      });
    }
  }
);

/* =========================================================
   REMINDERS - GET
========================================================= */

app.get(
  "/api/reminders",
  authMiddleware(["patient"]),
  async (req, res) => {
    try {
      const reminders =
        await Reminder.find({
          patientId:
            req.user.id,
        }).sort({
          date: 1,
          time: 1,
        });

      return res.json({
        status: "ok",
        reminders,
      });
    } catch (err) {
      console.error(
        "❌ Get reminders error:",
        err
      );

      return res.status(500).json({
        status: "error",
        message: err.message,
      });
    }
  }
);

/* =========================================================
   REMINDERS - UPDATE
========================================================= */

app.put(
  "/api/reminders/:id",
  authMiddleware(["patient"]),
  async (req, res) => {
    try {
      const reminderId =
        req.params.id;

      const updates =
        req.body;

      const reminder =
        await Reminder.findOneAndUpdate(
          {
            _id: reminderId,

            patientId:
              req.user.id,
          },
          updates,
          {
            new: true,
          }
        );

      if (!reminder) {
        return res.status(404).json({
          status: "error",
          message:
            "Reminder not found",
        });
      }

      return res.json({
        status: "ok",
        reminder,
      });
    } catch (err) {
      console.error(
        "❌ Update reminder error:",
        err
      );

      return res.status(500).json({
        status: "error",
        message: err.message,
      });
    }
  }
);

/* =========================================================
   REMINDERS - DELETE
========================================================= */

app.delete(
  "/api/reminders/:id",
  authMiddleware(["patient"]),
  async (req, res) => {
    try {
      const reminderId =
        req.params.id;

      const reminder =
        await Reminder.findOneAndDelete(
          {
            _id: reminderId,

            patientId:
              req.user.id,
          }
        );

      if (!reminder) {
        return res.status(404).json({
          status: "error",
          message:
            "Reminder not found",
        });
      }

      return res.json({
        status: "ok",
        message:
          "Reminder deleted",
      });
    } catch (err) {
      console.error(
        "❌ Delete reminder error:",
        err
      );

      return res.status(500).json({
        status: "error",
        message: err.message,
      });
    }
  }
);

/* =========================================================
   START SERVER
========================================================= */

app.listen(
  PORT,
  () => {
    console.log(
      `🚀 Server running on port ${PORT}`
    );

    console.log(
      `🔐 Google Login: ${
        GOOGLE_CLIENT_ID
          ? "CONFIGURED"
          : "NOT CONFIGURED"
      }`
    );
  }
);