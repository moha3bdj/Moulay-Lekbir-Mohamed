import DOMPurify from 'dompurify';

// Configure DOMPurify to allow valid internal portfolio UI handlers while blocking malicious payloads
DOMPurify.addHook('uponSanitizeAttribute', (node, data) => {
  if (data.attrName === 'onclick') {
    if (/^[a-zA-Z0-9_$]+\([^()]*\)$/.test(data.attrValue.trim())) {
      data.forceKeepAttr = true;
    }
  }
});

/**
 * Security: DOMPurify Sanitizer for all dynamic HTML injections
 */
function sanitizeHtml(dirty) {
  if (!dirty) return '';
  return DOMPurify.sanitize(dirty, {
    ADD_ATTR: [
      'target', 'rel', 'download', 'loading', 'draggable', 'data-index',
      'data-lang', 'data-i18n', 'aria-label', 'aria-hidden', 'aria-modal', 'role'
    ],
    ADD_TAGS: ['iframe']
  });
}

/**
 * Mohammed Abdeldjebar Moulay Lekbir - Portfolio Engine
 * Clean, lightweight, direct presentation focusing on KiCad & Embedded Systems.
 */

let appData = null;
let activeLightboxImages = [];
let activeLightboxIndex = 0;

// Embedded Fallback Data (KiCad PCB & Embedded Systems)
const fallbackData = {
  adminPasswordHash: '240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9',
  personal: {
    name: "Mohammed Abdeldjebar Moulay Lekbir",
    title: "Electrotechnics & Embedded Systems Engineer",
    subtitle: "KiCad PCB Designer & Embedded Systems Developer",
    avatar: "https://lh3.googleusercontent.com/d/1Jen7Dyb-DcCdHge8RQVyr436Np-zMkZt",
    location: "Algeria",
    bio: "Founder of Iotrixa (Arrêté 1275 labelized startup). Specialized in custom PCB schematic and layout design in KiCad, embedded firmware on STM32 & ESP32 with FreeRTOS, and motor control systems for competitive robotics.",
    email: "aedmoulay05@gmail.com",
    linkedin: "https://www.linkedin.com/in/moulay-lekbir-mohammed-abdeldjebar-a3526b307/",
    github: "https://github.com/moha3bdj",
    instagram: "",
    facebook: "",
    twitter: "",
    youtube: "",
    whatsapp: "",
    telegram: ""
  },
  projects: [
    {
      id: "iotrixa",
      title: "Iotrixa - Smart Control Hardware",
      category: "IoT & Telemetry",
      shortDesc: "Real-time IoT telemetry system using ESP32, custom power electronics, and cloud synchronization.",
      image: "https://lh3.googleusercontent.com/d/1OdZl6rIWL8K_4dGsrjwXaqwh9AJ06ex7",
      specs: {
        "Microcontroller": "ESP32-C3 Supermini RISC-V",
        "Power Supply": "HLK-PM01 AC-DC Step-Down (5V/3W)",
        "PCB Design Tool": "KiCad (Custom 1-Layer with Isolated Ground Plane)",
        "Actuation": "5V Relay Matrix (10A 250VAC)",
        "Protocols": "MQTT over TLS, WebSocket, Wi-Fi"
      },
      fullDescription: "Iotrixa is an industrial IoT hardware telemetry platform engineered for environmental monitoring and automated relay switching under Arrêté 1275.\n\nKey Highlights:\n• Custom 1-layer PCB designed in KiCad with isolated ground planes and snubber diodes to mitigate EMI.\n• ESP32 executing FreeRTOS tasks for real-time sensor polling and MQTT cloud sync.\n• Step-down buck power conversion with transient surge protection.",
      components: [
        "ESP32-C3 Supermini",
        "KiCad Custom PCB",
        "5V Relay (10A 250VAC)",
        "HLK-PM01 AC-DC",
        "MQTT Protocol",
        "Flyback Diode"
      ],
      gallery: [
        "https://lh3.googleusercontent.com/d/14n4-OrLAlPS-9uSSZP_Kg7XZ7Xjd8oU7",
        "https://lh3.googleusercontent.com/d/166oudlUfDTs6D-J8QjKwcwpxYJSRzZEV",
        "https://lh3.googleusercontent.com/d/16zXqYloh13SakZv38CfnPcarGeEWKhrK",
        "https://lh3.googleusercontent.com/d/19i4NiHQ-_rbfXI-OJQFH0RX6GitDrV6A",
        "https://lh3.googleusercontent.com/d/1DlffN5W6Gcgpsvox33mrfaRAvBJ4q2eL",
        "https://lh3.googleusercontent.com/d/1SVecvFFiVd9cvzWnlrDOmWw1dOFz9cA5",
        "https://lh3.googleusercontent.com/d/1_AR7gBROgjgEg4csMxfkBA85fp-UOkQZ",
        "https://lh3.googleusercontent.com/d/1a1DCVpvhaxXxcx-1s5C1dP4XuXcPyJ9S",
        "https://lh3.googleusercontent.com/d/1oIcaaPl_4lj258rPpZEit_5zHTjYnNJX",
        "https://lh3.googleusercontent.com/d/1tvvcmsO209lTFhpZoh2hUl_a609gSETZ"
      ],
      codeFilename: "telemetry_task.c",
      codeLanguage: "c",
      code: `/**
 * Iotrixa Smart Hardware - FreeRTOS Telemetry & Actuation Task
 * Target: ESP32-C3 Supermini RISC-V | Framework: ESP-IDF / Arduino
 */
#include <WiFi.h>
#include <PubSubClient.h>

#define RELAY_CH1_PIN    4
#define SENSOR_ADC_PIN   1
#define STATUS_LED_PIN   8

WiFiClient espClient;
PubSubClient mqttClient(espClient);

void vTelemetryTask(void *pvParameters) {
  char payload[128];
  for (;;) {
    int rawAdc = analogRead(SENSOR_ADC_PIN);
    float voltage = (rawAdc / 4095.0f) * 3.3f;
    
    snprintf(payload, sizeof(payload),
      "{\\"device\\":\\"iotrixa-01\\",\\"adc\\":%d,\\"volt\\":%.3f,\\"relay\\":%d}",
      rawAdc, voltage, digitalRead(RELAY_CH1_PIN));
    
    if (mqttClient.connected()) {
      mqttClient.publish("iotrixa/telemetry/nodes", payload);
    }
    vTaskDelay(pdMS_TO_TICKS(1000));
  }
}`
    },
    {
      id: "safebelt",
      title: "SafeBelt - Motor Controller & Safety Board",
      category: "Custom PCB",
      shortDesc: "High-density PCB featuring custom power distribution, STM32 control, and sensor interfaces.",
      image: "https://lh3.googleusercontent.com/d/1foFDBz4k-Q3PTBsqhG7wjFMqwpDfS2o7",
      specs: {
        "Microcontroller": "STM32F4 ARM Cortex-M4 (168MHz)",
        "PCB Design Tool": "KiCad (Multi-Layer Layout with Impedance Control)",
        "Signal Isolation": "High-Speed Optocouplers (PC817/6N137)",
        "Bus Interface": "RS-485 Differential Transceiver",
        "Protection": "Hardware Overcurrent Comparator + Crowbar"
      },
      fullDescription: "Engineered and fabricated for high-reliability embedded motor control and safety applications.\n\nKey Highlights:\n• Sub-microsecond hardware overcurrent shutoff circuit.\n• Opto-isolated signal paths shielding the STM32 microcontroller from motor switching noise.\n• High-speed differential RS485 communication.\n• Designed and routed entirely in KiCad.",
      components: [
        "KiCad Multi-Layer PCB",
        "STM32F4 Cortex-M4",
        "High-Speed Optocouplers",
        "RS-485 Transceiver",
        "SMD Passives",
        "Current Shunt Resistor"
      ],
      gallery: [
        "https://lh3.googleusercontent.com/d/14HEhjt_xihSt4vu5N8Enrdrhc5Rh9fGO",
        "https://lh3.googleusercontent.com/d/17kFic_dyWgOSquDR-ay_3A5K07x8m36X",
        "https://lh3.googleusercontent.com/d/1OhIw71AugEY3UUBSHKYRl6xN34gLg5Ro",
        "https://lh3.googleusercontent.com/d/1ViA3bChZzh80aOml1yFZcFS6-wjYkT8i",
        "https://lh3.googleusercontent.com/d/1bC_H7O5qoYa9VDIOnMa1NJamyfXFJH2y",
        "https://lh3.googleusercontent.com/d/1lrLhL459hESjPR8NMlnHXYMpj6erRv9v"
      ],
      codeFilename: "motor_fault_isr.c",
      codeLanguage: "c",
      code: `/**
 * SafeBelt High-Reliability Motor Controller
 * Target: STM32F401 ARM Cortex-M4 @ 84MHz
 * Sub-Microsecond Hardware Overcurrent Shutoff ISR
 */
#include "stm32f4xx_hal.h"

extern TIM_HandleTypeDef htim1;

void HAL_GPIO_EXTI_Callback(uint16_t GPIO_Pin) {
  if (GPIO_Pin == OVERCURRENT_COMP_PIN) {
    // Immediate hardware PWM disable (<450ns response)
    __HAL_TIM_MOE_DISABLE(&htim1);
    htim1.Instance->CCR1 = 0;
    htim1.Instance->CCR2 = 0;
    
    // Latch safety crowbar & activate optical fault signal
    HAL_GPIO_WritePin(FAULT_LATCH_PORT, FAULT_LATCH_PIN, GPIO_PIN_SET);
    HAL_GPIO_WritePin(STATUS_LED_PORT, STATUS_LED_PIN, GPIO_PIN_SET);
    
    RS485_BroadcastAlert(ALERT_CODE_OVERCURRENT);
  }
}`
    },
    {
      id: "robotics",
      title: "Autonomous Navigation Robot",
      category: "Robotics & Control",
      shortDesc: "Closed-loop motor drive and obstacle avoidance platform built for national robotics competitions.",
      image: "https://images.unsplash.com/photo-1485827404703-89b55fcc595e?w=800&auto=format&fit=crop&q=80",
      specs: {
        "Architecture": "High-Speed Microcontroller with Hardware PWM",
        "Control Algorithm": "Closed-Loop PID Velocity Control with Optical Encoders",
        "Perception": "Multi-Zone Ultrasonic Array + IR Proximity",
        "Power Supply": "4S LiPo Battery Pack (14.8V)",
        "Firmware": "Embedded C++"
      },
      fullDescription: "Custom autonomous wheeled robot constructed for national robotics competitions.\n\nKey Highlights:\n• Closed-loop PID velocity control using quadrature optical encoders.\n• Real-time ultrasonic ranging matrix calculating obstacle avoidance vectors.\n• High-current MOSFET H-bridge motor drive.",
      components: [
        "PID Motor Driver",
        "Ultrasonic Array",
        "Quadrature Encoders",
        "LiPo 4S Battery",
        "H-Bridge MOSFETs",
        "Embedded C++"
      ],
      gallery: [
        "https://images.unsplash.com/photo-1485827404703-89b55fcc595e?w=800&auto=format&fit=crop&q=80",
        "https://images.unsplash.com/photo-1517077304055-6e89abbf09b0?w=800&auto=format&fit=crop&q=80"
      ],
      codeFilename: "pid_velocity_controller.cpp",
      codeLanguage: "c",
      code: `/**
 * Autonomous Navigation Robot - Closed-Loop PID Velocity Controller
 * Quadrature Optical Encoder Feedback
 */
class VelocityPID {
private:
  float kp = 1.25f, ki = 0.08f, kd = 0.03f;
  float integral = 0.0f, lastError = 0.0f;
  float outputMin = -255.0f, outputMax = 255.0f;

public:
  float compute(float targetRPM, float measuredRPM, float dt) {
    float error = targetRPM - measuredRPM;
    integral += error * dt;
    if (integral > 100.0f) integral = 100.0f;
    else if (integral < -100.0f) integral = -100.0f;
    
    float derivative = (dt > 0.0f) ? (error - lastError) / dt : 0.0f;
    lastError = error;
    
    float output = (kp * error) + (ki * integral) + (kd * derivative);
    if (output > outputMax) return outputMax;
    if (output < outputMin) return outputMin;
    return output;
  }
};`
    }
  ],
  skills: [
    {
      category: "PCB Design & Hardware",
      items: [
        "KiCad Schematic & Layout",
        "Multi-Layer PCB Routing",
        "Ground Plane Isolation & EMI Reduction",
        "AC-DC Buck & Power Topologies",
        "SMD Soldering & Board Bring-Up"
      ]
    },
    {
      category: "Microcontrollers & Firmware",
      items: [
        "STM32 ARM Cortex-M (HAL / LL)",
        "ESP32 (C3, S3, WROOM)",
        "Embedded C / C++ & Python",
        "FreeRTOS Multi-Threading",
        "PID Motor Control & Encoders"
      ]
    },
    {
      category: "IoT & Protocols",
      items: [
        "MQTT over TLS",
        "RS-485 & Modbus RTU",
        "I2C, SPI & UART Buses",
        "Firebase Realtime DB",
        "Wi-Fi Telemetry & OTA"
      ]
    }
  ],
  milestones: [
    {
      year: "2024 - 2025",
      title: "Arrêté 1275 Startup Innovation Label (Iotrixa)",
      issuer: "Ministry of Higher Education & Scientific Research",
      description: "Government label recognizing Iotrixa as an innovative technology startup project for IoT telemetry and automated relay control systems."
    },
    {
      year: "Academic",
      title: "MCIL Electrotechnics & Embedded Systems Degree",
      issuer: "Faculty of Technology",
      description: "Specialized curriculum covering industrial electrotechnics, power distribution, microcontrollers, and closed-loop control systems."
    },
    {
      year: "2025",
      title: "National Robotics Championship Competitor",
      issuer: "National Robotics Tournament",
      description: "Lead hardware engineer: engineered autonomous wheeled robotic platform with PID velocity control and ultrasonic navigation."
    }
  ],
  resumeData: {
    "summary": "Electrotechnics & Embedded Systems Engineer and Founder of Iotrixa (Arrêté 1275). Experienced in KiCad PCB design, power electronics, and real-time firmware development in Embedded C/C++ on STM32 and ESP32 with FreeRTOS.",
    "education": [
      {
        "degree": "Master / MCIL in Electrotechnics & Embedded Systems",
        "institution": "Faculty of Technology",
        "period": "Specialized Program",
        "details": "Power electronics, industrial motor drives, STM32/ESP32 microcontrollers, and automation."
      }
    ],
    "experience": [
      {
        "role": "Founder & Lead Embedded Engineer",
        "organization": "Iotrixa (Arrêté 1275 Startup Project)",
        "period": "2024 - Present",
        "bulletPoints": [
          "Designed custom single and multi-layer PCBs in KiCad with isolated ground planes and transient protection.",
          "Architected IoT telemetry boards integrating ESP32-C3, AC-DC buck converters, and optoisolated relays.",
          "Implemented MQTT over TLS communications with cloud dashboards for remote telemetry."
        ]
      },
      {
        "role": "Hardware & Embedded Control Engineer",
        "organization": "National Robotics Tournament Team",
        "period": "2024 - 2025",
        "bulletPoints": [
          "Designed motor driver circuits and closed-loop PID velocity control firmware.",
          "Integrated ultrasonic sensor arrays and optical quadrature encoders for autonomous navigation."
        ]
      }
    ]
  },
  "resumeUrl": "resume.pdf",
  "resumeFilename": "Mohammed_Moulay_Lekbir_Resume.pdf"
};

/**
 * Storage & Auth Constants
 */
const STORAGE_KEY = 'portfolio_app_data';
const ADMIN_AUTH_KEY = 'portfolio_admin_logged_in';
const ADMIN_PASS_KEY = 'portfolio_admin_password';
const ADMIN_LOCKOUT_KEY = 'portfolio_admin_lockout';
const DEFAULT_ADMIN_EMAIL = 'aedmoulay05@gmail.com';
const DEFAULT_ADMIN_PASS_HASH = '240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9'; // SHA-256('admin123')
const THEME_KEY = 'portfolio_theme';
const LANG_KEY = 'portfolio_lang';

/**
 * Cross-Device Admin Password Resolver:
 * Hierarchy of active admin credentials:
 * 1. Vite Environment Variable (VITE_ADMIN_PASS_HASH) for Vercel/production deployment
 * 2. Browser Local Storage override (if modified on current device)
 * 3. Central repository data.json dataset (synchronized cross-device via commit)
 * 4. Stored pass fallback
 * 5. Default SHA-256 hash for 'admin123'
 */
function getActiveAdminPasswordHash() {
  try {
    if (typeof import.meta !== 'undefined' && import.meta.env && import.meta.env.VITE_ADMIN_PASS_HASH) {
      const envHash = String(import.meta.env.VITE_ADMIN_PASS_HASH).trim();
      if (envHash) return envHash;
    }
  } catch (e) {}

  const storedPass = localStorage.getItem(ADMIN_PASS_KEY);
  if (storedPass && storedPass !== DEFAULT_ADMIN_PASS_HASH && storedPass !== 'admin123') {
    return storedPass;
  }

  if (appData && appData.adminPasswordHash && typeof appData.adminPasswordHash === 'string') {
    const jsonHash = appData.adminPasswordHash.trim();
    if (jsonHash) return jsonHash;
  }

  if (storedPass) return storedPass;

  return DEFAULT_ADMIN_PASS_HASH;
}

function getActivePasswordSource() {
  try {
    if (typeof import.meta !== 'undefined' && import.meta.env && import.meta.env.VITE_ADMIN_PASS_HASH) {
      if (String(import.meta.env.VITE_ADMIN_PASS_HASH).trim()) {
        return 'Environment Variable (VITE_ADMIN_PASS_HASH)';
      }
    }
  } catch (e) {}

  const storedPass = localStorage.getItem(ADMIN_PASS_KEY);
  if (storedPass && storedPass !== DEFAULT_ADMIN_PASS_HASH && storedPass !== 'admin123') {
    return 'Local Device Storage';
  }

  if (appData && appData.adminPasswordHash && typeof appData.adminPasswordHash === 'string' && appData.adminPasswordHash !== DEFAULT_ADMIN_PASS_HASH) {
    return 'Synchronized data.json';
  }

  return 'Default Password (admin123)';
}

/**
 * Security: HTML entity escaping to prevent Stored & Reflected XSS
 */
function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

/**
 * Security: Sanitize URLs to prevent javascript: / data: pseudo-protocol injection
 */
function sanitizeUrl(url) {
  if (!url) return '';
  const trimmed = String(url).trim();
  if (/^(https?:|\/|mailto:|tel:)/i.test(trimmed)) {
    return trimmed;
  }
  return '#';
}

/**
 * Security: Prototype pollution prevention for JSON parsing & imports
 */
function sanitizeDataSchema(obj) {
  if (!obj || typeof obj !== 'object') return obj;
  const clean = Array.isArray(obj) ? [] : {};
  for (const key of Object.keys(obj)) {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
      continue;
    }
    const val = obj[key];
    if (val && typeof val === 'object') {
      clean[key] = sanitizeDataSchema(val);
    } else {
      clean[key] = val;
    }
  }
  return clean;
}

/**
 * Security: Cryptographic SHA-256 Hashing for admin password verification
 */
async function hashStringSHA256(str) {
  if (window.crypto && window.crypto.subtle) {
    try {
      const encoder = new TextEncoder();
      const data = encoder.encode(str);
      const hashBuf = await window.crypto.subtle.digest('SHA-256', data);
      return Array.from(new Uint8Array(hashBuf)).map(b => b.toString(16).padStart(2, '0')).join('');
    } catch (e) {
      console.warn('SubtleCrypto error, falling back', e);
    }
  }
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    hash = ((hash << 5) - hash) + str.charCodeAt(i);
    hash |= 0;
  }
  return String(hash);
}

let currentTheme = localStorage.getItem(THEME_KEY) || 'dark';
let currentLang = localStorage.getItem(LANG_KEY) || 'en';

/**
 * Multilingual Translations Engine (EN / FR / AR)
 */
const translations = {
  en: {
    navProjects: "Projects",
    navSkills: "Skills",
    navMilestones: "Milestones",
    navContact: "Contact",
    navResume: "Resume",
    navAdmin: "Admin",
    adminPortal: "Admin Portal",
    viewResume: "View Resume",
    lightMode: "Light Mode",
    darkMode: "Dark Mode",
    switchToLight: "Switch to Light Mode",
    switchToDark: "Switch to Dark Mode",

    heroStartupBadge: "Founder of Iotrixa • Arrêté 1275 Startup",
    heroRole: "KiCad PCB & Embedded Systems",
    heroName: "Mohammed Abdeldjebar Moulay Lekbir",
    heroSubtitle: "Electrotechnics & Embedded Systems Engineer • KiCad PCB Designer",
    heroBio: "Founder of <strong>Iotrixa</strong> (Arrêté 1275 startup). Specialized in custom PCB schematic and layout design in <strong>KiCad</strong>, embedded firmware on STM32 & ESP32 with FreeRTOS, and motor control systems for competitive robotics.",
    metric1Label: "Startup Label",
    metric2Label: "PCB Layout & Bring-Up",
    metric3Label: "Embedded Firmware",
    ctaExploreProjects: "View Projects",
    ctaViewResume: "View Resume",
    ctaContact: "Get in Touch",

    projectsEyebrow: "Selected Hardware & Firmware",
    projectsTitle: "Featured Projects",
    projectsSubtitle: "Custom KiCad PCB designs, industrial IoT telemetry hardware, and robotics motor drives. Explore interactive architecture specs, circuit topology, and board photography.",
    btnInspectSpecs: "Inspect Hardware & Schematics",
    photosCount: "photos",

    skillsEyebrow: "Technical Stack",
    skillsTitle: "Core Engineering & Tools",
    skillsSubtitle: "Mastery across KiCad hardware routing, microcontroller firmware architectures, and industrial telemetry.",

    milestonesEyebrow: "Trajectory",
    milestonesTitle: "Milestones & Credentials",
    milestonesSubtitle: "Startup labelization, academic degree in electrotechnics, and competitive robotics championships.",

    contactEyebrow: "Collaboration",
    contactTitle: "Let's Build Something Together",
    contactSubtitle: "Have a custom KiCad layout requirement, industrial telemetry project, or embedded firmware collaboration in mind?",
    directEmail: "Direct Email",
    linkedInLabel: "LinkedIn",
    gitHubLabel: "GitHub",
    gitHubSub: "@moha3bdj",
    instagramLabel: "Instagram",
    facebookLabel: "Facebook",
    twitterLabel: "Twitter / X",
    youtubeLabel: "YouTube",
    whatsappLabel: "WhatsApp",
    telegramLabel: "Telegram",
    btnCopyEmail: "Copy Email",
    copiedToast: "Email copied to clipboard!",
    footerCopy: "© 2026 Mohammed Abdeldjebar Moulay Lekbir • Founder of Iotrixa",
    footerTags: "KiCad PCB Design • Fusion 360 3D Modeling • Embedded Systems ",

    modalDetails: "Project Details",
    modalOverview: "Engineering Overview",
    modalSpecsHeader: "Hardware Specifications",
    modalBom: "Components & Bill of Materials",
    modalCodeHeader: "Firmware & Source Code",
    modalGallery: "PCB & Assembly Gallery",
    modalClose: "Close",
    copyCode: "Copy Code",
    copiedCode: "Copied!",
    resumeTitle: "Curriculum Vitae",
    resumeSub: "Pre-Uploaded PDF Document",
    resumePrint: "Print / PDF",
    resumeDownload: "Download PDF",
    resumeOpenNewTab: "Open in New Tab",
    resumeSummary: "Summary",
    resumeExperience: "Experience",
    resumeEducation: "Education"
  },
  fr: {
    navProjects: "Projets",
    navSkills: "Compétences",
    navMilestones: "Parcours",
    navContact: "Contact",
    navResume: "CV",
    navAdmin: "Admin",
    adminPortal: "Portail Admin",
    viewResume: "Voir le CV",
    lightMode: "Mode Clair",
    darkMode: "Mode Sombre",
    switchToLight: "Passer au Mode Clair",
    switchToDark: "Passer au Mode Sombre",

    heroStartupBadge: "Fondateur d'Iotrixa • Startup Labellisée Arrêté 1275",
    heroRole: "PCB KiCad & Systèmes Embarqués",
    heroName: "Mohammed Abdeldjebar Moulay Lekbir",
    heroSubtitle: "Ingénieur en Électrotechnique & Systèmes Embarqués • Concepteur PCB KiCad",
    heroBio: "Fondateur d'<strong>Iotrixa</strong> (startup labellisée Arrêté 1275). Spécialisé dans la conception et le routage de PCB sous <strong>KiCad</strong>, le firmware embarqué STM32 & ESP32 avec FreeRTOS, et le contrôle moteur pour la robotique de compétition.",
    metric1Label: "Label Startup",
    metric2Label: "Routage & Prototypage",
    metric3Label: "Firmware Embarqué",
    ctaExploreProjects: "Voir les Projets",
    ctaViewResume: "Voir le CV",
    ctaContact: "Me Contacter",

    projectsEyebrow: "Matériel & Firmware Sélectionnés",
    projectsTitle: "Projets Phares",
    projectsSubtitle: "Conceptions PCB KiCad sur mesure, matériel de télémétrie IoT industriel et commandes de moteurs robotiques. Explorez les spécifications et schémas interactifs.",
    btnInspectSpecs: "Examiner le Schéma & Spécifications",
    photosCount: "photos",

    skillsEyebrow: "Stack Technique",
    skillsTitle: "Ingénierie & Outils Clés",
    skillsSubtitle: "Maîtrise du routage matériel sous KiCad, des architectures firmware microcontrôleurs et de la télémétrie industrielle.",

    milestonesEyebrow: "Parcours & Réalisations",
    milestonesTitle: "Étapes Clés & Diplômes",
    milestonesSubtitle: "Labellisation startup (Arrêté 1275), diplôme en électrotechnique et championnats nationaux de robotique.",

    contactEyebrow: "Collaboration",
    contactTitle: "Construisons Quelque Chose Ensemble",
    contactSubtitle: "Vous avez un besoin de conception PCB sous KiCad, un projet de télémétrie IoT ou une collaboration en firmware embarqué ?",
    directEmail: "Email Direct",
    linkedInLabel: "LinkedIn",
    gitHubLabel: "GitHub",
    gitHubSub: "@moha3bdj • Matériel & Firmware",
    instagramLabel: "Instagram",
    facebookLabel: "Facebook",
    twitterLabel: "Twitter / X",
    youtubeLabel: "YouTube",
    whatsappLabel: "WhatsApp",
    telegramLabel: "Telegram",
    btnCopyEmail: "Copier l'Email",
    copiedToast: "Email copié dans le presse-papier !",
    footerCopy: "© 2026 Mohammed Abdeldjebar Moulay Lekbir • Fondateur d'Iotrixa",
    footerTags: "Matériel KiCad • Systèmes Embarqués • Ingénierie de Haute Précision",

    modalDetails: "Détails du Projet",
    modalOverview: "Aperçu de l'Ingénierie",
    modalSpecsHeader: "Spécifications Techniques",
    modalBom: "Composants & Nomenclature (BOM)",
    modalCodeHeader: "Code Source & Firmware",
    modalGallery: "Galerie PCB & Assemblage",
    modalClose: "Fermer",
    copyCode: "Copier le Code",
    copiedCode: "Copié !",
    resumeTitle: "Curriculum Vitae",
    resumeSub: "Document PDF Officiel",
    resumePrint: "Imprimer / PDF",
    resumeDownload: "Télécharger le PDF",
    resumeOpenNewTab: "Ouvrir dans un nouvel onglet",
    resumeSummary: "Profil Professionnel",
    resumeExperience: "Expérience Professionnelle",
    resumeEducation: "Formation & Diplômes"
  },
  ar: {
    navProjects: "المشاريع",
    navSkills: "المهارات",
    navMilestones: "المحطات",
    navContact: "تواصل معي",
    navResume: "السيرة الذاتية",
    navAdmin: "لوحة الإدارة",
    adminPortal: "بوابة الإدارة",
    viewResume: "عرض السيرة الذاتية",
    lightMode: "الوضع النهاري",
    darkMode: "الوضع الليلي",
    switchToLight: "التبديل إلى الوضع النهاري",
    switchToDark: "التبديل إلى الوضع الليلي",

    heroStartupBadge: "مؤسس شركة Iotrixa • مشروع مبتكر القرار الوزاري 1275",
    heroRole: "تصميم لوحات KiCad والأنظمة المدمجة",
    heroName: "محمد عبد الجبار مولاي لكبير",
    heroSubtitle: "مهندس كهرتقني وأنظمة مدمجة • مصمم لوحات إلكترونية KiCad",
    heroBio: "مؤسس مشروع <strong>Iotrixa</strong> (الحاصل على علامة مشروع مبتكر - القرار 1275). متخصص في تصميم ومخططات وتوجيه الدوائر الإلكترونية المطبوعة عبر <strong>KiCad</strong>، وتطوير الأنظمة المدمجة على STM32 و ESP32 مع أنظمة FreeRTOS، والتحكم في محركات الروبوتات التنافسية.",
    metric1Label: "علامة مشروع مبتكر",
    metric2Label: "توجيه وتصنيع اللوحات",
    metric3Label: "البرمجيات المدمجة",
    ctaExploreProjects: "استعراض المشاريع",
    ctaViewResume: "السيرة الذاتية",
    ctaContact: "تواصل معي",

    projectsEyebrow: "العتاد المختار والبرمجيات المدمجة",
    projectsTitle: "المشاريع البارزة",
    projectsSubtitle: "تصاميم PCB احترافية عبر KiCad، وعتاد القياس والتحكم عن بعد للإنترنت الصناعي، ومحركات الروبوتات التنافسية. استكشف المواصفات والمخططات التفصيلية.",
    btnInspectSpecs: "معاينة العتاد والمخططات",
    photosCount: "صور",

    skillsEyebrow: "المهارات التقنية",
    skillsTitle: "الأدوات والمهارات الهندسية",
    skillsSubtitle: "إتقان تصميم وتوجيه الدوائر الإلكترونية KiCad، وبرمجة الأنظمة المدمجة، والقياس والتحكم عن بعد في البيئات الصناعية.",

    milestonesEyebrow: "المسار والإنجازات",
    milestonesTitle: "المحطات والشهادات",
    milestonesSubtitle: "نيل علامة مشروع مبتكر، الشهادة التخصصية في الهندسة الكهرتقنية، ومشاركات البطولات الوطنية للروبوتات.",

    contactEyebrow: "التعاون الهندسي",
    contactTitle: "لنقم ببناء مشروع متميز معاً",
    contactSubtitle: "هل لديك متطلبات لتصميم دوائر إلكترونية عبر KiCad، أو مشروع إنترنت الأشياء والقياس عن بعد، أو تطوير برمجيات مدمجة؟",
    directEmail: "البريد الإلكتروني",
    linkedInLabel: "لينكد إن (LinkedIn)",
    gitHubLabel: "جيت هاب (GitHub)",
    gitHubSub: "@moha3bdj • العتاد والبرمجيات",
    instagramLabel: "إنستغرام (Instagram)",
    facebookLabel: "فيسبوك (Facebook)",
    twitterLabel: "تويتر / إكس (Twitter/X)",
    youtubeLabel: "يوتيوب (YouTube)",
    whatsappLabel: "واتساب (WhatsApp)",
    telegramLabel: "تيليجرام (Telegram)",
    btnCopyEmail: "نسخ البريد الإلكتروني",
    copiedToast: "تم نسخ البريد الإلكتروني بنجاح!",
    footerCopy: "© 2026 محمد عبد الجبار مولاي لكبير • مؤسس Iotrixa",
    footerTags: "عتاد KiCad • أنظمة مدمجة • هندسة إلكترونية دقيقة",

    modalDetails: "تفاصيل المشروع",
    modalOverview: "نظرة هندسية عامة",
    modalSpecsHeader: "المواصفات التقنية للعتاد",
    modalBom: "المكونات وقائمة المواد (BOM)",
    modalCodeHeader: "البرمجيات المدمجة والكود",
    modalGallery: "معرض اللوحات والتجميع",
    modalClose: "إغلاق",
    copyCode: "نسخ الكود",
    copiedCode: "تم النسخ!",
    resumeTitle: "السيرة الذاتية المهنية",
    resumeSub: "ملف السيرة الذاتية (PDF)",
    resumePrint: "طباعة / PDF",
    resumeDownload: "تحميل السيرة الذاتية (PDF)",
    resumeOpenNewTab: "فتح في نافذة جديدة",
    resumeSummary: "الملخص المهني",
    resumeExperience: "الخبرات العملية والمشاريع",
    resumeEducation: "المؤهلات العلمية"
  }
};

const categoryTranslations = {
  "IoT & Telemetry": { fr: "IoT & Télémétrie", ar: "إنترنت الأشياء والقياس عن بعد" },
  "Custom PCB": { fr: "PCB Sur-Mesure", ar: "تصميم دوائر PCB مخصصة" },
  "Robotics & Control": { fr: "Robotique & Contrôle", ar: "الروبوتات وأنظمة التحكم" }
};

const specsTranslations = {
  "Microcontroller": { fr: "Microcontrôleur", ar: "الميكروكنترولر" },
  "Power Supply": { fr: "Alimentation", ar: "التغذية الكهربائية" },
  "PCB Design Tool": { fr: "Outil de Conception PCB", ar: "برنامج تصميم PCB" },
  "Actuation": { fr: "Actionnement", ar: "المشغلات والتحكم" },
  "Protocols": { fr: "Protocoles", ar: "بروتوكولات الاتصال" },
  "Architecture": { fr: "Architecture", ar: "البنية المعمارية" },
  "Control Algorithm": { fr: "Algorithme de Contrôle", ar: "خوارزمية التحكم" },
  "Perception": { fr: "Perception & Capteurs", ar: "الاستشعار والإدراك" },
  "Signal Isolation": { fr: "Isolation du Signal", ar: "عزل الإشارة" },
  "Bus Interface": { fr: "Interface de Bus", ar: "واجهة الناقل" },
  "Protection": { fr: "Protection Matérielle", ar: "دوائر الحماية" },
  "Firmware": { fr: "Firmware", ar: "البرمجيات المدمجة" }
};

const localizedProjects = {
  iotrixa: {
    fr: {
      title: "Iotrixa - Matériel de Contrôle Intelligent",
      category: "IoT & Télémétrie",
      shortDesc: "Système de télémétrie IoT en temps réel avec ESP32, électronique de puissance sur mesure et synchronisation cloud.",
      fullDescription: "Iotrixa est une plateforme matérielle de télémétrie IoT industrielle développée pour la surveillance environnementale et la commutation automatisée de relais sous le label Arrêté 1275.\n\nPoints Clés :\n• PCB simple couche conçu sous KiCad avec plans de masse isolés et diodes de roue libre contre les perturbations EMI.\n• ESP32 exécutant des tâches FreeRTOS pour l'acquisition de capteurs en temps réel et la synchronisation cloud MQTT.\n• Conversion de puissance abaisseuse (Buck) avec protection contre les surtensions transitoires."
    },
    ar: {
      title: "Iotrixa - عتاد التحكم الذكي",
      category: "إنترنت الأشياء والقياس عن بعد",
      shortDesc: "منظومة قياس وتحكم بالإنترنت الصناعي في الوقت الحقيقي بمعالج ESP32، وإلكترونيات قدرة مخصصة، ومزامنة سحابية.",
      fullDescription: "منصة Iotrixa هي عتاد صناعي لإنترنت الأشياء والقياس عن بعد، مصممة للمراقبة البيئية والتحكم الآلي بالمرحلات ضمن مشروع القرار الوزاري 1275.\n\nأبرز المزايا الهندسية:\n• لوحة PCB مخصصة أحادية الطبقة صُممت عبر KiCad مع مساحات أرضي معزولة وثنائيات حماية للحد من التداخل الكهرومغناطيسي.\n• معالج ESP32 يدير مهام FreeRTOS متعددة الخيوط لقراءة الحساسات والمزامنة السحابية عبر MQTT.\n• دارة تحويل جهد خافض مدمجة مع حماية ضد الارتفاعات المفاجئة للجهد."
    }
  },
  safebelt: {
    fr: {
      title: "SafeBelt - Carte de Sécurité & Contrôleur Moteur",
      category: "PCB Sur-Mesure",
      shortDesc: "PCB haute densité avec distribution de puissance sur mesure, commande STM32 et interfaces capteurs.",
      fullDescription: "Conçu et fabriqué pour le contrôle moteur embarqué à haute fiabilité et les applications de sécurité.\n\nPoints Clés :\n• Circuit de coupure matérielle en cas de surintensité en moins d'une microseconde.\n• Voies de signaux opto-isolées protégeant le microcontrôleur STM32 des parasites moteurs.\n• Communication différentielle RS-485 à haute vitesse.\n• Conçu et routé intégralement sous KiCad."
    },
    ar: {
      title: "SafeBelt - لوحة التحكم بالمحركات والسلامة",
      category: "تصميم دوائر PCB مخصصة",
      shortDesc: "لوحة PCB عالية الكثافة لتوزيع القدرة والتحكم عبر ميكروكنترولر STM32 وواجهات عزل الإشارة.",
      fullDescription: "صُممت ونُفذت للتحكم عالي الاعتمادية في المحركات وتطبيقات السلامة الصناعية.\n\nأبرز المزايا الهندسية:\n• دارة فصل كهروميكانيكية فائقة السرعة للتيار الزائد في أقل من ميكروثانية.\n• مسارات إشارة معزولة ضوئياً لعزل معالج STM32 عن ضوضاء المحركات.\n• واجهة اتصال تفاضلية RS-485 لنقل البيانات بسرعة وثبات.\n• صُممت ونُفذت مساراتها بالكامل باستخدام KiCad."
    }
  },
  robotics: {
    fr: {
      title: "Robot Autonome de Navigation",
      category: "Robotique & Contrôle",
      shortDesc: "Plateforme de commande moteur en boucle fermée et évitement d'obstacles conçue pour les compétitions nationales de robotique.",
      fullDescription: "Robot mobile autonome sur roues construit pour les compétitions nationales de robotique.\n\nPoints Clés :\n• Régulation de vitesse PID en boucle fermée via encodeurs optiques en quadrature.\n• Matrice de télémétrie ultrasonique en temps réel calculant les trajectoires d'évitement.\n• Pont en H haute puissance à transistors MOSFET."
    },
    ar: {
      title: "روبوت الملاحة الذاتية",
      category: "الروبوتات وأنظمة التحكم",
      shortDesc: "منصة تحكم مغلقة بالمحركات وتفادي العوائق مطورة لبطولات الروبوتات الوطنية.",
      fullDescription: "روبوت ذكي متحرك مطور للمشاركة والمنافسة في البطولات الوطنية للروبوتات.\n\nأبرز المزايا الهندسية:\n• تحكم PID في السرعة بحلقة مغلقة باستخدام مشفرات بصرية تربيعية.\n• مصفوفة حساسات فوق صوتية في الوقت الحقيقي لتحديد وتفادي العوائق.\n• دارة قيادة محركات بجسر H عالي التيار بواسطة ترانزستورات MOSFET."
    }
  }
};

const localizedSkillsCategories = {
  "PCB Design & Hardware": { fr: "Conception PCB & Matériel", ar: "تصميم دوائر PCB والعتاد" },
  "Microcontrollers & Firmware": { fr: "Microcontrôleurs & Firmware", ar: "الميكروكنترولر والبرمجيات المدمجة" },
  "IoT & Protocols": { fr: "IoT & Protocoles Réseau", ar: "إنترنت الأشياء وبروتوكولات الاتصال" }
};

const localizedMilestones = [
  {
    fr: {
      year: "2024 - 2025",
      title: "Label Projet Innovant - Arrêté 1275 (Iotrixa)",
      issuer: "Ministère de l'Enseignement Supérieur",
      description: "Reconnaissance officielle d'Iotrixa comme projet de startup technologique innovante dans la télémétrie IoT et les relais automatisés."
    },
    ar: {
      year: "2024 - 2025",
      title: "علامة مشروع مبتكر - القرار الوزاري 1275 (Iotrixa)",
      issuer: "وزارة التعليم العالي والبحث العلمي",
      description: "وسام حكومي يعتمد مشروع Iotrixa كشركة ناشئة تكنولوجية مبتكرة في مجال إنترنت الأشياء والقياس والتحكم عن بعد."
    }
  },
  {
    fr: {
      year: "Diplôme",
      title: "Master / MCIL en Électrotechnique & Systèmes Embarqués",
      issuer: "Faculté de Technologie",
      description: "Formation spécialisée en électrotechnique industrielle, électronique de puissance, microcontrôleurs et commande en boucle fermée."
    },
    ar: {
      year: "المسار الأكاديمي",
      title: "شهادة ماستر / MCIL كهرتقني وأنظمة مدمجة",
      issuer: "كلية التكنولوجيا",
      description: "تخصص في الإلكترونيات الصناعية، وإلكترونيات القدرة، وبرمجة الميكروكنترولر، وأنظمة التحكم الآلي ذات الحلقة المغلقة."
    }
  },
  {
    fr: {
      year: "2025",
      title: "Compétiteur au Championnat National de Robotique",
      issuer: "Tournoi National de Robotique",
      description: "Ingénieur matériel principal : conception d'une plateforme robotique mobile autonome avec régulation PID et navigation ultrasonique."
    },
    ar: {
      year: "2025",
      title: "مشارك في البطولة الوطنية للروبوتات",
      issuer: "البطولة الوطنية للروبوتات",
      description: "مهندس العتاد الرئيسي: تصميم روبوت متحرك ذاتي القيادة مع خوارزميات PID للسرعة والملاحة بالموجات فوق الصوتية."
    }
  }
];

const localizedResume = {
  fr: {
    summary: "Ingénieur en Électrotechnique & Systèmes Embarqués et Fondateur d'Iotrixa (Arrêté 1275). Expérimenté en conception de PCB sous KiCad, électronique de puissance et développement de firmware temps réel en C/C++ embarqué sur STM32 et ESP32 avec FreeRTOS.",
    education: [
      {
        degree: "Master / MCIL en Électrotechnique & Systèmes Embarqués",
        institution: "Faculté de Technologie",
        period: "Programme Spécialisé",
        details: "Électronique de puissance, commandes de moteurs industriels, microcontrôleurs STM32/ESP32 et automatismes."
      }
    ],
    experience: [
      {
        role: "Fondateur & Ingénieur Système Embarqué Principal",
        organization: "Iotrixa (Projet de Startup Arrêté 1275)",
        period: "2024 - Présent",
        bulletPoints: [
          "Conception de PCB simple et multi-couches sous KiCad avec plans de masse isolés et protection transitoire.",
          "Architecture de cartes de télémétrie IoT intégrant ESP32-C3, convertisseurs Buck AC-DC et relais opto-isolés.",
          "Mise en œuvre des communications MQTT sous TLS avec tableaux de bord cloud pour la télémétrie à distance."
        ]
      },
      {
        role: "Ingénieur Matériel & Contrôle Embarqué",
        organization: "Équipe du Tournoi National de Robotique",
        period: "2024 - 2025",
        bulletPoints: [
          "Conception des circuits de commande de moteurs et firmware de régulation de vitesse PID en boucle fermée.",
          "Intégration de matrices de capteurs ultrasoniques et encodeurs optiques en quadrature pour la navigation autonome."
        ]
      }
    ]
  },
  ar: {
    summary: "مهندس كهرتقني وأنظمة مدمجة ومؤسس مشروع Iotrixa (القرار 1275). خبير في تصميم لوحات الدوائر الإلكترونية المطبوعة عبر KiCad، وإلكترونيات القدرة، وتطوير برمجيات الأنظمة المدمجة في الوقت الحقيقي بلغة C/C++ على معالجات STM32 و ESP32 مع FreeRTOS.",
    education: [
      {
        degree: "ماستر / مهندس في الكهرتقني والأنظمة المدمجة",
        institution: "كلية التكنولوجيا",
        period: "برنامج تخصصي",
        details: "إلكترونيات القدرة، قيادة المحركات الصناعية، ميكروكنترولر STM32 و ESP32 والتحكم الآلي."
      }
    ],
    experience: [
      {
        role: "مؤسس ومهندس أنظمة مدمجة رئيسي",
        organization: "مشروع Iotrixa (مشروع مبتكر القرار 1275)",
        period: "2024 - حتى الآن",
        bulletPoints: [
          "تصميم لوحات PCB أحادية ومتعددة الطبقات عبر KiCad مع مستويات أرضي معزولة وحماية ضد الارتفاعات الفولتية.",
          "هندسة لوحات قياس وتحكم IoT تدمج معالج ESP32-C3 ومحولات جهد AC-DC ومرحلات معزولة ضوئياً.",
          "تنفيذ بروتوكول MQTT الآمن عبر TLS مع لوحات تحكم سحابية للرصد والتحكم عن بُعد."
        ]
      },
      {
        role: "مهندس عتاد وتحكم مدمج",
        organization: "فريق البطولة الوطنية للروبوتات",
        period: "2024 - 2025",
        bulletPoints: [
          "تصميم دارات قيادة المحركات وبرمجة خوارزميات PID للتحكم في السرعة بحلقة مغلقة.",
          "دمج مصفوفات الحساسات فوق الصوتية والمشفرات الضوئية للملاحة الذاتية وتفادي الحواجز."
        ]
      }
    ]
  }
};

/**
 * Localization & Theme Helpers
 */
function t(key) {
  if (translations[currentLang] && translations[currentLang][key]) {
    return translations[currentLang][key];
  }
  if (translations['en'] && translations['en'][key]) {
    return translations['en'][key];
  }
  return key;
}

function getLocalizedCategory(cat) {
  if (categoryTranslations[cat] && categoryTranslations[cat][currentLang]) {
    return categoryTranslations[cat][currentLang];
  }
  return cat;
}

function getLocalizedProject(p) {
  if (currentLang !== 'en' && localizedProjects[p.id] && localizedProjects[p.id][currentLang]) {
    const loc = localizedProjects[p.id][currentLang];
    return {
      title: loc.title || p.title,
      category: loc.category || getLocalizedCategory(p.category),
      shortDesc: loc.shortDesc || p.shortDesc,
      fullDescription: loc.fullDescription || p.fullDescription
    };
  }
  return {
    title: p.title,
    category: getLocalizedCategory(p.category),
    shortDesc: p.shortDesc,
    fullDescription: p.fullDescription
  };
}

function getLocalizedSkillCategory(catName) {
  if (localizedSkillsCategories[catName] && localizedSkillsCategories[catName][currentLang]) {
    return localizedSkillsCategories[catName][currentLang];
  }
  return catName;
}

function getLocalizedMilestone(m, idx) {
  if (currentLang !== 'en' && localizedMilestones[idx] && localizedMilestones[idx][currentLang]) {
    const loc = localizedMilestones[idx][currentLang];
    return {
      year: loc.year || m.year,
      title: loc.title || m.title,
      issuer: loc.issuer || m.issuer,
      description: loc.description || m.description
    };
  }
  return m;
}

function getLocalizedResume(r) {
  if (currentLang !== 'en' && localizedResume[currentLang]) {
    return localizedResume[currentLang];
  }
  return r;
}

function applyStaticTranslations() {
  document.querySelectorAll('[data-i18n]').forEach(el => {
    const key = el.getAttribute('data-i18n');
    const val = t(key);
    if (val && val !== key) {
      el.innerHTML = sanitizeHtml(val);
    }
  });
}

function applyTheme(theme) {
  currentTheme = theme;
  document.documentElement.setAttribute('data-theme', theme);
  localStorage.setItem(THEME_KEY, theme);

  const isLight = theme === 'light';
  const themeIcon = document.getElementById('theme-icon');
  const mobileThemeIcon = document.getElementById('mobile-theme-icon');
  const mobileThemeLabel = document.getElementById('mobile-theme-label');
  const themeToggleBtn = document.getElementById('theme-toggle-btn');

  if (themeIcon) {
    themeIcon.className = isLight ? 'fa-solid fa-moon' : 'fa-solid fa-sun';
  }
  if (mobileThemeIcon) {
    mobileThemeIcon.className = isLight ? 'fa-solid fa-moon' : 'fa-solid fa-sun';
  }
  if (mobileThemeLabel) {
    mobileThemeLabel.innerText = isLight ? t('darkMode') : t('lightMode');
  }
  if (themeToggleBtn) {
    themeToggleBtn.setAttribute('title', isLight ? t('switchToDark') : t('switchToLight'));
    themeToggleBtn.setAttribute('aria-label', isLight ? t('switchToDark') : t('switchToLight'));
  }
}

function toggleTheme() {
  const next = currentTheme === 'light' ? 'dark' : 'light';
  applyTheme(next);
}

function setLanguage(lang) {
  if (!translations[lang]) lang = 'en';
  currentLang = lang;
  localStorage.setItem(LANG_KEY, lang);

  document.documentElement.setAttribute('lang', lang);
  if (lang === 'ar') {
    document.documentElement.setAttribute('dir', 'rtl');
  } else {
    document.documentElement.setAttribute('dir', 'ltr');
  }

  const currentLangLabel = document.getElementById('current-lang-label');
  if (currentLangLabel) {
    currentLangLabel.innerText = lang.toUpperCase();
  }

  document.querySelectorAll('.lang-option').forEach(btn => {
    btn.classList.toggle('active', btn.getAttribute('data-lang') === lang);
  });
  document.querySelectorAll('.mobile-lang-pill').forEach(btn => {
    btn.classList.toggle('active', btn.getAttribute('data-lang') === lang);
  });

  closeLangDropdown();
  applyStaticTranslations();

  // Re-render components with localized dynamic strings
  if (appData) {
    renderHero();
    renderProjects();
    renderSkills();
    renderMilestones();
    renderContactCards();
    setupResumeModal();
  }
  applyTheme(currentTheme);
}

function toggleLangDropdown(event) {
  if (event) event.stopPropagation();
  const switcher = document.getElementById('lang-switcher');
  if (!switcher) return;
  const isOpen = switcher.classList.contains('open');
  switcher.classList.toggle('open', !isOpen);
  const toggleBtn = document.getElementById('lang-toggle-btn');
  if (toggleBtn) toggleBtn.setAttribute('aria-expanded', !isOpen ? 'true' : 'false');
}

function closeLangDropdown() {
  const switcher = document.getElementById('lang-switcher');
  if (switcher) {
    switcher.classList.remove('open');
    const toggleBtn = document.getElementById('lang-toggle-btn');
    if (toggleBtn) toggleBtn.setAttribute('aria-expanded', 'false');
  }
}

/**
 * Initialize Portfolio
 */
async function initPortfolio() {
  // Apply saved theme & language immediately
  applyTheme(currentTheme);
  setLanguage(currentLang);

  // Check local storage for persistent user-modulated data
  const savedData = localStorage.getItem(STORAGE_KEY);
  if (savedData) {
    try {
      appData = JSON.parse(savedData);
    } catch (e) {
      console.warn('Could not parse localStorage portfolio data, falling back to data.json', e);
    }
  }

  if (!appData) {
    try {
      const res = await fetch('data.json', { cache: 'no-cache' });
      if (res.ok) {
        appData = await res.json();
      } else {
        appData = fallbackData;
      }
    } catch (e) {
      appData = fallbackData;
    }
  }

  renderHero();
  renderProjects();
  renderSkills();
  renderMilestones();
  renderContactCards();
  setupResumeModal();

  initNavigation();
  initBackToTop();
  initAdminMode();
  setupProjectEditorEvents();
}

/**
 * Persist Application Data & Re-render
 */
function saveAppData(toastMessage = 'Changes saved successfully') {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(appData));
  } catch (err) {
    console.error('Failed to save to localStorage', err);
  }

  renderHero();
  renderProjects();
  renderSkills();
  renderMilestones();
  renderContactCards();
  setupResumeModal();
  updateAdminUI();

  // If admin control panel is open, refresh tab counts and views
  const adminPanel = document.getElementById('admin-panel-modal');
  if (adminPanel && adminPanel.classList.contains('active')) {
    updateAdminTabCounts();
    populateAdminProjectsList();
    populateAdminSkillsList();
    populateAdminMilestonesList();
    populateAdminResume();
  }

  if (toastMessage) {
    showToast(toastMessage);
  }
}

/**
 * 1. Hero
 */
function renderHero() {
  const p = appData.personal || fallbackData.personal;
  const isDefaultBio = (!appData.personal || appData.personal.bio === fallbackData.personal.bio);

  const navAvatar = document.getElementById('nav-avatar');
  if (navAvatar) navAvatar.src = p.avatar;

  const navName = document.getElementById('nav-name');
  if (navName) navName.innerText = (currentLang === 'ar' && isDefaultBio) ? t('heroName') : p.name;

  const heroAvatarImg = document.getElementById('hero-avatar-img');
  if (heroAvatarImg) heroAvatarImg.src = p.avatar;

  const heroName = document.getElementById('hero-name');
  if (heroName) heroName.innerText = (currentLang === 'ar' && isDefaultBio) ? t('heroName') : p.name;

  const heroSubtitle = document.getElementById('hero-subtitle');
  if (heroSubtitle) {
    heroSubtitle.innerText = isDefaultBio ? t('heroSubtitle') : (p.subtitle || `${p.title} • KiCad PCB Designer`);
  }

  const heroBio = document.getElementById('hero-bio');
  if (heroBio) {
    heroBio.innerHTML = sanitizeHtml(isDefaultBio ? t('heroBio') : (p.bio || ''));
  }

  const linkEmail = document.getElementById('link-email');
  if (linkEmail) linkEmail.href = `https://mail.google.com/mail/?view=cm&fs=1&to=${p.email}`;

  const emailDisplay = document.getElementById('footer-email-text');
  if (emailDisplay) emailDisplay.innerText = p.email;

  const linkLinkedin = document.getElementById('link-linkedin');
  if (linkLinkedin) linkLinkedin.href = p.linkedin;

  const linkGithub = document.getElementById('link-github');
  if (linkGithub) linkGithub.href = p.github;

  // In-line Admin button in Hero
  const ctaGroup = document.querySelector('.hero-cta-group');
  if (ctaGroup) {
    const existingBtn = document.getElementById('btn-hero-admin-edit');
    if (existingBtn) existingBtn.remove();
    if (isAdminLoggedIn()) {
      const editBtn = document.createElement('button');
      editBtn.id = 'btn-hero-admin-edit';
      editBtn.className = 'btn btn-outline admin-only';
      editBtn.style.borderColor = 'var(--accent-primary)';
      editBtn.style.color = 'var(--accent-primary)';
      editBtn.innerHTML = sanitizeHtml('<i class="fa-solid fa-pen-to-square"></i> Edit Profile');
      editBtn.onclick = () => openAdminControlPanel('profile');
      ctaGroup.appendChild(editBtn);
    }
  }
}

/**
 * 2. Projects (High-Precision Hardware & Firmware Showcase)
 */
function renderProjects() {
  const grid = document.getElementById('projects-grid');
  if (!grid || !appData.projects) return;

  grid.innerHTML = sanitizeHtml(appData.projects.map((p, idx) => {
    const images = p.gallery && p.gallery.length > 0 ? p.gallery : [p.image];
    let mediaMarkup = '';

    if (images.length >= 3) {
      const extraCount = images.length - 3;
      mediaMarkup = `
        <div class="project-media-collage">
          <img src="${sanitizeUrl(images[0])}" class="collage-item collage-main" alt="${escapeHtml(p.title)}" loading="lazy">
          <img src="${sanitizeUrl(images[1])}" class="collage-item" alt="${escapeHtml(p.title)}" loading="lazy">
          <div class="collage-more">
            <img src="${sanitizeUrl(images[2])}" class="collage-item" alt="${escapeHtml(p.title)}" loading="lazy">
            ${extraCount > 0 ? `<div class="collage-overlay">+${extraCount} ${escapeHtml(t('photosCount'))}</div>` : ''}
          </div>
        </div>
      `;
    } else {
      mediaMarkup = `<img src="${sanitizeUrl(p.image)}" alt="${escapeHtml(p.title)}" class="project-single-img" loading="lazy">`;
    }

    const isFeatured = idx === 0;
    const catIcon = (p.category || '').includes('IoT') ? 'fa-tower-broadcast' : (p.category || '').includes('PCB') ? 'fa-microchip' : 'fa-robot';
    const loc = getLocalizedProject(p);
    const safeId = escapeHtml(p.id);

    const adminToolbar = isAdminLoggedIn() ? `
      <div class="project-card-admin-bar" onclick="event.stopPropagation()">
        <button onclick="openProjectEditModal('${safeId}')" class="admin-card-btn" title="Edit Project"><i class="fa-solid fa-pen"></i> Edit</button>
        <button onclick="deleteProject('${safeId}')" class="admin-card-btn admin-card-btn-del" title="Delete Project"><i class="fa-solid fa-trash"></i> Delete</button>
      </div>
    ` : '';

    return `
      <article class="project-card ${isFeatured ? 'project-featured' : ''}" onclick="openProjectModal('${safeId}')" tabindex="0" role="button" aria-label="View ${escapeHtml(loc.title)}">
        ${adminToolbar}
        <div class="project-media-wrapper">
          ${mediaMarkup}
          <div class="project-category-badge">
            <i class="fa-solid ${catIcon}"></i>
            <span>${escapeHtml(loc.category)}</span>
          </div>
        </div>
        <div class="project-card-body">
          <div class="project-card-header">
            <h3 class="project-card-title">${escapeHtml(loc.title)}</h3>
          </div>
          <p class="project-card-desc">${escapeHtml(loc.shortDesc)}</p>
          <div class="project-tech-tags">
            ${(p.components || []).slice(0, 4).map(c => `<span class="tech-chip">${escapeHtml(c)}</span>`).join('')}
          </div>
          <div class="project-card-action">
            <span>${escapeHtml(t('btnInspectSpecs'))}</span>
            <i class="fa-solid fa-arrow-right"></i>
          </div>
        </div>
      </article>
    `;
  }).join(''));
}

/**
 * 3. Technical Skills
 */
function renderSkills() {
  const grid = document.getElementById('skills-grid');
  if (!grid || !appData.skills) return;

  const categoryIcons = {
    "PCB Design & Hardware": "fa-microchip",
    "Microcontrollers & Firmware": "fa-bolt",
    "IoT & Protocols": "fa-network-wired"
  };

  grid.innerHTML = sanitizeHtml(appData.skills.map((cat, catIdx) => {
    const iconClass = categoryIcons[cat.category] || "fa-layer-group";
    const locCat = getLocalizedSkillCategory(cat.category);

    const adminActions = isAdminLoggedIn() ? `
      <div style="display: flex; gap: 0.35rem; margin-top: 0.75rem;">
        <button onclick="addSkillItem(${catIdx})" class="admin-card-btn" style="padding: 0.2rem 0.5rem;"><i class="fa-solid fa-plus"></i> Add Item</button>
        <button onclick="deleteSkillCategory(${catIdx})" class="admin-card-btn admin-card-btn-del" style="padding: 0.2rem 0.5rem;"><i class="fa-solid fa-trash"></i> Delete</button>
      </div>
    ` : '';

    const countLabel = currentLang === 'ar' ? `${cat.items.length} كفاءات رئيسية` : currentLang === 'fr' ? `${cat.items.length} Compétences Clés` : `${cat.items.length} Core Capabilities`;

    return `
      <div class="skill-card">
        <div class="skill-card-header">
          <div class="skill-icon-box">
            <i class="fa-solid ${iconClass}"></i>
          </div>
          <div style="flex-grow: 1;">
            <h3 class="skill-card-title">${escapeHtml(locCat)}</h3>
            <span class="skill-card-count">${escapeHtml(countLabel)}</span>
          </div>
        </div>
        <ul class="skill-items-list">
          ${cat.items.map((item, itemIdx) => `
            <li class="skill-item">
              <span class="skill-check-icon"><i class="fa-solid fa-check"></i></span>
              <span class="skill-text">${escapeHtml(item)}</span>
              ${isAdminLoggedIn() ? `<button onclick="removeSkillItem(${catIdx}, ${itemIdx})" class="admin-card-btn admin-card-btn-del" style="margin-left: auto; padding: 0.1rem 0.35rem;" title="Remove"><i class="fa-solid fa-xmark"></i></button>` : ''}
            </li>
          `).join('')}
        </ul>
        ${adminActions}
      </div>
    `;
  }).join(''));
}

/**
 * 4. Milestones & Reordering
 */
let draggedMilestoneIdx = null;

function handleMilestoneDragStart(e, idx) {
  draggedMilestoneIdx = idx;
  if (e.dataTransfer) {
    e.dataTransfer.effectAllowed = 'move';
    e.dataTransfer.setData('text/plain', String(idx));
  }
  const el = e.currentTarget;
  setTimeout(() => {
    if (el) el.classList.add('dragging');
  }, 0);
}

function handleMilestoneDragOver(e, idx) {
  e.preventDefault();
  if (e.dataTransfer) {
    e.dataTransfer.dropEffect = 'move';
  }
  const el = e.currentTarget;
  if (draggedMilestoneIdx !== null && draggedMilestoneIdx !== idx) {
    el.classList.add('drag-over');
  }
}

function handleMilestoneDragLeave(e, idx) {
  e.currentTarget.classList.remove('drag-over');
}

function handleMilestoneDrop(e, targetIdx) {
  e.preventDefault();
  e.stopPropagation();
  e.currentTarget.classList.remove('drag-over');

  if (draggedMilestoneIdx === null || draggedMilestoneIdx === targetIdx) {
    draggedMilestoneIdx = null;
    return;
  }

  const [movedItem] = appData.milestones.splice(draggedMilestoneIdx, 1);
  appData.milestones.splice(targetIdx, 0, movedItem);
  draggedMilestoneIdx = null;

  saveAppData('Milestones reordered successfully');
  populateAdminMilestonesList();
}

function handleMilestoneDragEnd(e) {
  draggedMilestoneIdx = null;
  document.querySelectorAll('.timeline-item, .admin-list-item').forEach(el => {
    el.classList.remove('dragging', 'drag-over');
  });
}

function moveMilestone(idx, direction) {
  if (!appData.milestones) return;
  const targetIdx = idx + direction;
  if (targetIdx < 0 || targetIdx >= appData.milestones.length) return;
  const [movedItem] = appData.milestones.splice(idx, 1);
  appData.milestones.splice(targetIdx, 0, movedItem);
  saveAppData('Milestone position moved');
  populateAdminMilestonesList();
}

function renderMilestones() {
  const container = document.getElementById('milestones-list');
  if (!container || !appData.milestones) return;

  const icons = ["fa-award", "fa-graduation-cap", "fa-trophy"];
  const loggedIn = isAdminLoggedIn();

  container.innerHTML = sanitizeHtml(`
    <div class="timeline-container">
      ${appData.milestones.map((m, idx) => {
    const icon = icons[idx % icons.length];
    const loc = getLocalizedMilestone(m, idx);
    const dragAttrs = loggedIn ? `
          draggable="true"
          data-index="${idx}"
          ondragstart="handleMilestoneDragStart(event, ${idx})"
          ondragover="handleMilestoneDragOver(event, ${idx})"
          ondragleave="handleMilestoneDragLeave(event, ${idx})"
          ondrop="handleMilestoneDrop(event, ${idx})"
          ondragend="handleMilestoneDragEnd(event)"
        ` : '';

    const adminActions = loggedIn ? `
          <div style="display: flex; align-items: center; justify-content: space-between; gap: 0.5rem; margin-top: 0.85rem; padding-top: 0.65rem; border-top: 1px dashed var(--border-subtle); flex-wrap: wrap;">
            <div style="display: flex; align-items: center; gap: 0.35rem;">
              <span class="milestone-drag-handle" title="Drag to reorder position in timeline"><i class="fa-solid fa-grip-vertical"></i> Drag</span>
              <button type="button" onclick="moveMilestone(${idx}, -1)" ${idx === 0 ? 'disabled' : ''} class="admin-card-btn" title="Move milestone up"><i class="fa-solid fa-arrow-up"></i></button>
              <button type="button" onclick="moveMilestone(${idx}, 1)" ${idx === appData.milestones.length - 1 ? 'disabled' : ''} class="admin-card-btn" title="Move milestone down"><i class="fa-solid fa-arrow-down"></i></button>
              <span style="font-size: 0.72rem; color: var(--text-muted); font-family: var(--font-mono); margin-left: 0.25rem;">#${idx + 1}</span>
            </div>
            <div style="display: flex; gap: 0.4rem;">
              <button type="button" onclick="openMilestoneEditModal(${idx})" class="admin-card-btn"><i class="fa-solid fa-pen"></i> Edit</button>
              <button type="button" onclick="deleteMilestone(${idx})" class="admin-card-btn admin-card-btn-del"><i class="fa-solid fa-trash"></i> Delete</button>
            </div>
          </div>
        ` : '';

    return `
          <div class="timeline-item ${loggedIn ? 'is-admin-draggable' : ''}" ${dragAttrs}>
            <div class="timeline-track">
              <div class="timeline-node">
                <i class="fa-solid ${icon}"></i>
              </div>
              ${idx < appData.milestones.length - 1 ? '<div class="timeline-line"></div>' : ''}
            </div>
            <div class="timeline-content">
              <div class="timeline-meta">
                <span class="timeline-year">${escapeHtml(loc.year)}</span>
                <span class="timeline-issuer"><i class="fa-solid fa-building-columns"></i> ${escapeHtml(loc.issuer)}</span>
              </div>
              <h3 class="timeline-title">${escapeHtml(loc.title)}</h3>
              <p class="timeline-desc">${escapeHtml(loc.description)}</p>
              ${adminActions}
            </div>
          </div>
        `;
  }).join('')}
    </div>
  `);
}

/**
 * 4.5. Centered Contact Cards & Social Channels Modulation
 */
function renderContactCards() {
  const container = document.getElementById('contact-cards-grid');
  if (!container) return;

  const p = (appData && appData.personal) || fallbackData.personal;
  const cards = [];

  // 1. Direct Email (always primary)
  const email = p.email || 'aedmoulay05@gmail.com';
  cards.push(`
    <a href="mailto:${email}" class="contact-card" id="contact-card-email" title="Send email to ${email}">
      <div class="contact-card-icon"><i class="fa-solid fa-envelope"></i></div>
      <div class="contact-card-details">
        <span class="contact-card-label">${t('directEmail') || 'Direct Email'}</span>
        <span class="contact-card-val">${email}</span>
      </div>
      <div class="contact-card-arrow"><i class="fa-solid fa-arrow-right"></i></div>
    </a>
  `);

  // 2. LinkedIn
  if (p.linkedin && p.linkedin.trim()) {
    cards.push(`
      <a href="${p.linkedin}" target="_blank" rel="noopener noreferrer" class="contact-card" id="contact-card-linkedin" title="LinkedIn Profile">
        <div class="contact-card-icon"><i class="fa-brands fa-linkedin-in"></i></div>
        <div class="contact-card-details">
          <span class="contact-card-label">${t('linkedInLabel') || 'LinkedIn'}</span>
          <span class="contact-card-val">Moulay Lekbir Mohammed</span>
        </div>
        <div class="contact-card-arrow"><i class="fa-solid fa-arrow-up-right-from-square"></i></div>
      </a>
    `);
  }

  // 3. GitHub
  if (p.github && p.github.trim()) {
    cards.push(`
      <a href="${p.github}" target="_blank" rel="noopener noreferrer" class="contact-card" id="contact-card-github" title="GitHub Profile">
        <div class="contact-card-icon"><i class="fa-brands fa-github"></i></div>
        <div class="contact-card-details">
          <span class="contact-card-label">${t('gitHubLabel') || 'GitHub'}</span>
          <span class="contact-card-val">@moha3bdj</span>
        </div>
        <div class="contact-card-arrow"><i class="fa-solid fa-arrow-up-right-from-square"></i></div>
      </a>
    `);
  }

  // 4. Instagram
  if (p.instagram && p.instagram.trim()) {
    const rawVal = p.instagram.trim();
    const url = rawVal.startsWith('http') ? rawVal : `https://instagram.com/${rawVal.replace('@', '')}`;
    const displayVal = rawVal.startsWith('http') ? (rawVal.split('/').filter(Boolean).pop() || 'Instagram') : (rawVal.startsWith('@') ? rawVal : `@${rawVal}`);
    cards.push(`
      <a href="${url}" target="_blank" rel="noopener noreferrer" class="contact-card" id="contact-card-instagram" title="Instagram Profile">
        <div class="contact-card-icon" style="color: #E1306C; background: rgba(225, 48, 108, 0.12);"><i class="fa-brands fa-instagram"></i></div>
        <div class="contact-card-details">
          <span class="contact-card-label">${t('instagramLabel') || 'Instagram'}</span>
          <span class="contact-card-val">${displayVal}</span>
        </div>
        <div class="contact-card-arrow"><i class="fa-solid fa-arrow-up-right-from-square"></i></div>
      </a>
    `);
  }

  // 5. Facebook
  if (p.facebook && p.facebook.trim()) {
    const rawVal = p.facebook.trim();
    const url = rawVal.startsWith('http') ? rawVal : `https://facebook.com/${rawVal}`;
    const displayVal = rawVal.startsWith('http') ? (rawVal.split('/').filter(Boolean).pop() || 'Facebook') : rawVal;
    cards.push(`
      <a href="${url}" target="_blank" rel="noopener noreferrer" class="contact-card" id="contact-card-facebook" title="Facebook Profile">
        <div class="contact-card-icon" style="color: #1877F2; background: rgba(24, 119, 242, 0.12);"><i class="fa-brands fa-facebook"></i></div>
        <div class="contact-card-details">
          <span class="contact-card-label">${t('facebookLabel') || 'Facebook'}</span>
          <span class="contact-card-val">${displayVal}</span>
        </div>
        <div class="contact-card-arrow"><i class="fa-solid fa-arrow-up-right-from-square"></i></div>
      </a>
    `);
  }

  // 6. Twitter / X
  if (p.twitter && p.twitter.trim()) {
    const rawVal = p.twitter.trim();
    const url = rawVal.startsWith('http') ? rawVal : `https://x.com/${rawVal.replace('@', '')}`;
    const displayVal = rawVal.startsWith('http') ? (rawVal.split('/').filter(Boolean).pop() || 'Twitter') : (rawVal.startsWith('@') ? rawVal : `@${rawVal}`);
    cards.push(`
      <a href="${url}" target="_blank" rel="noopener noreferrer" class="contact-card" id="contact-card-twitter" title="Twitter / X Profile">
        <div class="contact-card-icon"><i class="fa-brands fa-x-twitter"></i></div>
        <div class="contact-card-details">
          <span class="contact-card-label">${t('twitterLabel') || 'Twitter / X'}</span>
          <span class="contact-card-val">${displayVal}</span>
        </div>
        <div class="contact-card-arrow"><i class="fa-solid fa-arrow-up-right-from-square"></i></div>
      </a>
    `);
  }

  // 7. YouTube
  if (p.youtube && p.youtube.trim()) {
    const rawVal = p.youtube.trim();
    const url = rawVal.startsWith('http') ? rawVal : `https://youtube.com/${rawVal.startsWith('@') ? rawVal : '@' + rawVal}`;
    const displayVal = rawVal.startsWith('http') ? (rawVal.split('/').filter(Boolean).pop() || 'YouTube') : rawVal;
    cards.push(`
      <a href="${url}" target="_blank" rel="noopener noreferrer" class="contact-card" id="contact-card-youtube" title="YouTube Channel">
        <div class="contact-card-icon" style="color: #FF0000; background: rgba(255, 0, 0, 0.12);"><i class="fa-brands fa-youtube"></i></div>
        <div class="contact-card-details">
          <span class="contact-card-label">${t('youtubeLabel') || 'YouTube'}</span>
          <span class="contact-card-val">${displayVal}</span>
        </div>
        <div class="contact-card-arrow"><i class="fa-solid fa-arrow-up-right-from-square"></i></div>
      </a>
    `);
  }

  // 8. WhatsApp
  if (p.whatsapp && p.whatsapp.trim()) {
    const rawVal = p.whatsapp.trim();
    const cleanNum = rawVal.replace(/[^0-9]/g, '');
    const url = rawVal.startsWith('http') ? rawVal : `https://wa.me/${cleanNum}`;
    cards.push(`
      <a href="${url}" target="_blank" rel="noopener noreferrer" class="contact-card" id="contact-card-whatsapp" title="Chat on WhatsApp">
        <div class="contact-card-icon" style="color: #25D366; background: rgba(37, 211, 102, 0.12);"><i class="fa-brands fa-whatsapp"></i></div>
        <div class="contact-card-details">
          <span class="contact-card-label">${t('whatsappLabel') || 'WhatsApp'}</span>
          <span class="contact-card-val">${rawVal}</span>
        </div>
        <div class="contact-card-arrow"><i class="fa-solid fa-arrow-up-right-from-square"></i></div>
      </a>
    `);
  }

  // 9. Telegram
  if (p.telegram && p.telegram.trim()) {
    const rawVal = p.telegram.trim();
    const cleanUser = rawVal.replace('@', '').replace(/https?:\/\/t\.me\//, '');
    const url = rawVal.startsWith('http') ? rawVal : `https://t.me/${cleanUser}`;
    cards.push(`
      <a href="${url}" target="_blank" rel="noopener noreferrer" class="contact-card" id="contact-card-telegram" title="Chat on Telegram">
        <div class="contact-card-icon" style="color: #229ED9; background: rgba(34, 158, 217, 0.12);"><i class="fa-brands fa-telegram"></i></div>
        <div class="contact-card-details">
          <span class="contact-card-label">${t('telegramLabel') || 'Telegram'}</span>
          <span class="contact-card-val">@${cleanUser}</span>
        </div>
        <div class="contact-card-arrow"><i class="fa-solid fa-arrow-up-right-from-square"></i></div>
      </a>
    `);
  }

  // 10. Admin Quick Panel Link (if logged in)
  if (isAdminLoggedIn()) {
    cards.push(`
      <button type="button" onclick="openAdminControlPanel()" class="contact-card" id="contact-card-admin" title="Open Admin Panel" style="border-style: dashed; border-color: var(--accent-primary); width: 100%; text-align: left; background: none; font: inherit; cursor: pointer;">
        <div class="contact-card-icon"><i class="fa-solid fa-sliders"></i></div>
        <div class="contact-card-details">
          <span class="contact-card-label" style="color: var(--accent-primary);">Admin Mode</span>
          <span class="contact-card-val">Modulate Channels &amp; Data</span>
        </div>
        <div class="contact-card-arrow"><i class="fa-solid fa-arrow-right"></i></div>
      </button>
    `);
  }

  container.innerHTML = sanitizeHtml(cards.join(''));
}

/**
 * 5. Project Modal
 */
function openProjectModal(id) {
  const p = (appData.projects || []).find(proj => proj.id === id);
  if (!p) return;

  const loc = getLocalizedProject(p);
  const catIcon = (p.category || '').includes('IoT') ? 'fa-tower-broadcast' : (p.category || '').includes('PCB') ? 'fa-microchip' : 'fa-robot';

  document.getElementById('modal-title').innerText = loc.title;
  const catEl = document.getElementById('modal-category');
  if (catEl) {
    catEl.innerHTML = sanitizeHtml(`<i class="fa-solid ${catIcon}"></i> ${loc.category} &bull; ${t('modalSpecsHeader')}`);
  }
  document.getElementById('modal-project-img').src = sanitizeUrl(p.image);
  document.getElementById('modal-desc').innerText = loc.fullDescription || loc.shortDesc;

  // Specs
  const specsTable = document.getElementById('modal-specs-table');
  specsTable.innerHTML = sanitizeHtml(Object.entries(p.specs || {}).map(([k, v]) => {
    const locKey = (specsTranslations[k] && specsTranslations[k][currentLang]) || k;
    return `<tr><td>${escapeHtml(locKey)}</td><td>${escapeHtml(v)}</td></tr>`;
  }).join(''));

  // Components
  const compList = document.getElementById('modal-components-list');
  compList.innerHTML = sanitizeHtml((p.components || []).map(c => `
    <span class="modal-tech-chip">${escapeHtml(c)}</span>
  `).join(''));

  // Firmware & Source Code
  const codeSection = document.getElementById('modal-code-section');
  if (codeSection) {
    if (p.code && p.code.trim()) {
      codeSection.style.display = 'block';
      const filenameEl = document.getElementById('modal-code-filename');
      const badgeEl = document.getElementById('modal-code-badge');
      const contentEl = document.getElementById('modal-code-content');

      const langLabels = {
        c: 'C / C++',
        arduino: 'Arduino',
        python: 'Python',
        rust: 'Rust',
        verilog: 'Verilog',
        bash: 'Bash',
        json: 'JSON',
        kicad: 'KiCad',
        plaintext: 'Plain Text'
      };

      if (filenameEl) filenameEl.innerText = p.codeFilename || 'firmware.c';
      if (badgeEl) badgeEl.innerText = langLabels[p.codeLanguage] || (p.codeLanguage || 'Code').toUpperCase();
      if (contentEl) contentEl.textContent = p.code;
    } else {
      codeSection.style.display = 'none';
    }
  }

  // Gallery
  const allImages = p.gallery && p.gallery.length > 0 ? p.gallery : [p.image];
  activeLightboxImages = allImages;
  const galGrid = document.getElementById('modal-gallery-grid');
  galGrid.innerHTML = sanitizeHtml(allImages.map((img, i) => `
    <div class="modal-gallery-thumb" onclick="openLightbox(activeLightboxImages, ${i})">
      <img src="${sanitizeUrl(img)}" alt="${escapeHtml(loc.title)}" loading="lazy">
    </div>
  `).join(''));

  document.getElementById('project-modal').classList.add('active');
  document.body.style.overflow = 'hidden';
}

function closeProjectModal() {
  const modal = document.getElementById('project-modal');
  if (modal) modal.classList.remove('active');
  document.body.style.overflow = '';
}

/**
 * 6. Lightbox
 */
function openLightbox(images, startIndex = 0) {
  activeLightboxImages = images;
  activeLightboxIndex = startIndex;
  document.getElementById('lightbox-img').src = activeLightboxImages[activeLightboxIndex];
  document.getElementById('lightbox-overlay').classList.add('active');
  document.body.style.overflow = 'hidden';
}

function closeLightbox() {
  document.getElementById('lightbox-overlay').classList.remove('active');
  const projectModal = document.getElementById('project-modal');
  if (!projectModal || !projectModal.classList.contains('active')) {
    document.body.style.overflow = '';
  }
}

function nextLightboxImage(e) {
  if (e) e.stopPropagation();
  if (activeLightboxImages.length <= 1) return;
  activeLightboxIndex = (activeLightboxIndex + 1) % activeLightboxImages.length;
  document.getElementById('lightbox-img').src = activeLightboxImages[activeLightboxIndex];
}

function prevLightboxImage(e) {
  if (e) e.stopPropagation();
  if (activeLightboxImages.length <= 1) return;
  activeLightboxIndex = (activeLightboxIndex - 1 + activeLightboxImages.length) % activeLightboxImages.length;
  document.getElementById('lightbox-img').src = activeLightboxImages[activeLightboxIndex];
}

window.addEventListener('keydown', (e) => {
  const lb = document.getElementById('lightbox-overlay');
  if (lb && lb.classList.contains('active')) {
    if (e.key === 'Escape') closeLightbox();
    if (e.key === 'ArrowRight') nextLightboxImage();
    if (e.key === 'ArrowLeft') prevLightboxImage();
  } else {
    if (e.key === 'Escape') {
      closeProjectModal();
      closeResumeModal();
      closeAdminAuthModal();
      closeAdminControlPanel();
      closeProjectEditModal();
      closeMilestoneEditModal();
      closeExperienceEditModal();
      closeEducationEditModal();
      closeJsonPasteModal();
    }
  }

  // Keyboard shortcut Ctrl+Shift+A or Cmd+Shift+A to toggle Admin
  if ((e.ctrlKey || e.metaKey) && e.shiftKey && (e.key === 'A' || e.key === 'a')) {
    e.preventDefault();
    toggleAdminAuth();
  }
});

/**
 * 7. Resume Modal (Pre-Uploaded PDF Viewer)
 */
function getResumePdfUrl() {
  return localStorage.getItem('portfolio_custom_resume_pdf') || (appData && appData.resumeUrl) || 'resume.pdf';
}

function setupResumeModal() {
  const content = document.getElementById('resume-content');
  if (!content) return;

  const pdfUrl = getResumePdfUrl();
  const filename = (appData && appData.resumeFilename) || 'Mohammed_Moulay_Lekbir_Resume.pdf';

  // Update top download & newtab links
  const topDownloadBtn = document.getElementById('resume-download-btn-top');
  if (topDownloadBtn) {
    topDownloadBtn.href = pdfUrl;
    topDownloadBtn.setAttribute('download', filename);
  }
  const topNewTabBtn = document.getElementById('resume-newtab-btn-top');
  if (topNewTabBtn) {
    topNewTabBtn.href = pdfUrl;
  }
  const bottomDownloadBtn = document.getElementById('resume-download-btn-bottom');
  if (bottomDownloadBtn) {
    bottomDownloadBtn.href = pdfUrl;
    bottomDownloadBtn.setAttribute('download', filename);
  }

  content.innerHTML = sanitizeHtml(`
    <div class="resume-pdf-container">
      <iframe src="${pdfUrl}#toolbar=1&navpanes=0" class="resume-pdf-frame" id="resume-pdf-iframe" title="Mohammed Moulay Lekbir Resume PDF"></iframe>
      <div class="resume-pdf-fallback">
        <div class="resume-fallback-info">
          <div class="resume-fallback-icon"><i class="fa-solid fa-file-pdf"></i></div>
          <div class="resume-fallback-text">
            <h4>Mohammed Abdeldjebar Moulay Lekbir</h4>
            <p>Electrotechnics & Embedded Systems Engineer • KiCad PCB Designer (Official PDF)</p>
          </div>
        </div>
        <div class="resume-fallback-actions">
          <a href="${pdfUrl}" target="_blank" rel="noopener noreferrer" class="btn btn-secondary btn-sm">
            <i class="fa-solid fa-arrow-up-right-from-square"></i> <span data-i18n="resumeOpenNewTab">${t('resumeOpenNewTab')}</span>
          </a>
          <a href="${pdfUrl}" download="${filename}" class="btn btn-primary btn-sm">
            <i class="fa-solid fa-download"></i> <span data-i18n="resumeDownload">${t('resumeDownload')}</span>
          </a>
        </div>
      </div>
    </div>
  `);
}

function openResumeModal() {
  setupResumeModal();
  document.getElementById('resume-modal').classList.add('active');
  document.body.style.overflow = 'hidden';
}

function closeResumeModal() {
  document.getElementById('resume-modal').classList.remove('active');
  document.body.style.overflow = '';
}

function printResume() {
  const pdfUrl = getResumePdfUrl();
  const iframe = document.getElementById('resume-pdf-iframe');
  if (iframe && iframe.contentWindow) {
    try {
      iframe.contentWindow.print();
      return;
    } catch (e) { }
  }
  window.open(pdfUrl, '_blank', 'noopener,noreferrer');
}

/**
 * 8. Admin Authentication & Session Management
 */
function isAdminLoggedIn() {
  return localStorage.getItem(ADMIN_AUTH_KEY) === 'true';
}

function initAdminMode() {
  updateAdminUI();
  checkAdminUrlTrigger();
}

function toggleAdminAuth() {
  if (isAdminLoggedIn()) {
    openAdminControlPanel();
  } else {
    openAdminAuthModal();
  }
}

function openAdminAuthModal() {
  const modal = document.getElementById('admin-login-modal');
  if (modal) {
    const alert = document.getElementById('admin-login-alert');
    if (alert) alert.style.display = 'none';
    const emailInput = document.getElementById('admin-email-input');
    if (emailInput) emailInput.value = DEFAULT_ADMIN_EMAIL;
    const passInput = document.getElementById('admin-password-input');
    if (passInput) passInput.value = '';

    const hintEl = document.getElementById('admin-pass-hint');
    if (hintEl) {
      const activeHash = getActiveAdminPasswordHash();
      if (activeHash === DEFAULT_ADMIN_PASS_HASH) {
        hintEl.innerHTML = `Default password: <code class="code-tag">admin123</code> (customizable in Security settings)`;
      } else {
        hintEl.innerHTML = `<i class="fa-solid fa-shield-halved" style="color: var(--accent-primary);"></i> Secured with custom admin password`;
      }
    }

    modal.classList.add('active');
    document.body.style.overflow = 'hidden';
    setTimeout(() => passInput && passInput.focus(), 150);
  }
}

function closeAdminAuthModal() {
  const modal = document.getElementById('admin-login-modal');
  if (modal) modal.classList.remove('active');
  document.body.style.overflow = '';
}

async function handleAdminLogin(e) {
  if (e) e.preventDefault();
  const alertEl = document.getElementById('admin-login-alert');

  // Rate limiting / Brute-force protection
  const now = Date.now();
  let lockout = { attempts: 0, lockUntil: 0 };
  try {
    const raw = localStorage.getItem(ADMIN_LOCKOUT_KEY);
    if (raw) lockout = JSON.parse(raw);
  } catch (err) {}

  if (lockout.lockUntil && now < lockout.lockUntil) {
    const remainingSecs = Math.ceil((lockout.lockUntil - now) / 1000);
    if (alertEl) {
      alertEl.style.display = 'block';
      alertEl.innerHTML = sanitizeHtml(`<i class="fa-solid fa-lock"></i> Security Lockout: Too many failed attempts. Try again in <b>${remainingSecs}s</b>.`);
    }
    return;
  }

  const email = (document.getElementById('admin-email-input').value || '').trim();
  const password = document.getElementById('admin-password-input').value || '';

  const activeHash = getActiveAdminPasswordHash();
  const inputHash = await hashStringSHA256(password);

  const isPasswordValid = (
    inputHash === activeHash ||
    password === activeHash ||
    (activeHash === DEFAULT_ADMIN_PASS_HASH && password === 'admin123')
  );

  if (email.toLowerCase() === DEFAULT_ADMIN_EMAIL.toLowerCase() && isPasswordValid) {
    // Reset lockout counter on successful authentication
    localStorage.removeItem(ADMIN_LOCKOUT_KEY);
    // Ensure validated hash is saved to this device's storage
    localStorage.setItem(ADMIN_PASS_KEY, activeHash);
    localStorage.setItem(ADMIN_AUTH_KEY, 'true');
    closeAdminAuthModal();
    updateAdminUI();
    renderHero();
    renderProjects();
    renderSkills();
    renderMilestones();
    renderContactCards();
    setupResumeModal();
    showToast(`Welcome Mohammed! Admin Mode active.`);
  } else {
    lockout.attempts = (lockout.attempts || 0) + 1;
    if (lockout.attempts >= 5) {
      lockout.lockUntil = now + 5 * 60 * 1000; // 5-minute cooldown
      localStorage.setItem(ADMIN_LOCKOUT_KEY, JSON.stringify(lockout));
      if (alertEl) {
        alertEl.style.display = 'block';
        alertEl.innerHTML = sanitizeHtml(`<i class="fa-solid fa-triangle-exclamation"></i> Too many failed attempts. Login locked for 5 minutes.`);
      }
      return;
    }
    localStorage.setItem(ADMIN_LOCKOUT_KEY, JSON.stringify(lockout));
    if (alertEl) {
      alertEl.style.display = 'block';
      alertEl.innerHTML = sanitizeHtml(`<i class="fa-solid fa-circle-exclamation"></i> Invalid email or password. Attempt ${lockout.attempts} of 5.`);
    }
  }
}

function logoutAdmin() {
  localStorage.removeItem(ADMIN_AUTH_KEY);
  updateAdminUI();
  renderHero();
  renderProjects();
  renderSkills();
  renderMilestones();
  renderContactCards();
  setupResumeModal();
  closeAdminControlPanel();
  showToast('Logged out of Admin Mode');
}

function togglePasswordVisibility(inputId, btn) {
  const input = document.getElementById(inputId);
  if (!input) return;
  const isPass = input.type === 'password';
  input.type = isPass ? 'text' : 'password';
  if (btn) {
    btn.innerHTML = sanitizeHtml(isPass ? '<i class="fa-solid fa-eye-slash"></i>' : '<i class="fa-solid fa-eye"></i>');
  }
}

function updateAdminUI() {
  const loggedIn = isAdminLoggedIn();
  const adminBar = document.getElementById('admin-bar');
  if (adminBar) {
    adminBar.style.display = loggedIn ? 'block' : 'none';
  }

  // Admin access buttons are hidden for public visitors
  const adminBtn = document.getElementById('btn-admin-access');
  if (adminBtn) {
    adminBtn.style.display = loggedIn ? 'inline-flex' : 'none';
    if (loggedIn) {
      adminBtn.className = 'btn btn-primary btn-sm';
      const icon = document.getElementById('btn-admin-icon');
      const label = document.getElementById('btn-admin-label');
      if (icon) icon.className = 'fa-solid fa-lock-open';
      if (label) label.innerText = 'Admin Active';
    }
  }

  const mobileAdminBtn = document.getElementById('btn-mobile-admin');
  if (mobileAdminBtn) {
    mobileAdminBtn.style.display = loggedIn ? 'inline-flex' : 'none';
    if (loggedIn) {
      mobileAdminBtn.innerHTML = sanitizeHtml('<i class="fa-solid fa-lock-open"></i> Admin Active');
    }
  }

  const footerAdminLink = document.getElementById('link-admin-footer');
  const footerDotSep = document.querySelector('.footer-dot-sep');
  if (footerAdminLink) {
    footerAdminLink.style.display = loggedIn ? 'inline-flex' : 'none';
  }
  if (footerDotSep) {
    footerDotSep.style.display = loggedIn ? 'inline' : 'none';
  }
}

let secretAdminClicks = 0;
let secretAdminTimer = null;
function handleSecretAdminTrigger() {
  secretAdminClicks++;
  clearTimeout(secretAdminTimer);
  if (secretAdminClicks >= 3) {
    secretAdminClicks = 0;
    toggleAdminAuth();
  } else {
    secretAdminTimer = setTimeout(() => {
      secretAdminClicks = 0;
    }, 1200);
  }
}

function checkAdminUrlTrigger() {
  try {
    const urlParams = new URLSearchParams(window.location.search);
    const hash = window.location.hash;
    if (urlParams.has('admin') || hash === '#admin') {
      setTimeout(() => {
        toggleAdminAuth();
      }, 250);
    }
  } catch (e) { }
}

/**
 * 9. Admin Control Panel (Dashboard)
 */
function openAdminControlPanel(tab = 'profile') {
  if (!isAdminLoggedIn()) {
    openAdminAuthModal();
    return;
  }
  const modal = document.getElementById('admin-panel-modal');
  if (!modal) return;

  modal.classList.add('active');
  document.body.style.overflow = 'hidden';

  switchAdminTab(tab);
  updateAdminTabCounts();
  populateProfileForm();
  populateAdminProjectsList();
  populateAdminSkillsList();
  populateAdminMilestonesList();
  populateAdminResume();
  populateAdminSecurityInfo();
}

function closeAdminControlPanel() {
  const modal = document.getElementById('admin-panel-modal');
  if (modal) modal.classList.remove('active');
  document.body.style.overflow = '';
}

function switchAdminTab(tabName) {
  document.querySelectorAll('.admin-tab-btn').forEach(btn => {
    btn.classList.toggle('active', btn.id === `tab-btn-${tabName}`);
  });
  document.querySelectorAll('.admin-tab-content').forEach(content => {
    content.classList.toggle('active', content.id === `admin-tab-${tabName}`);
  });
  if (tabName === 'security') {
    populateAdminSecurityInfo();
  }
}

function updateAdminTabCounts() {
  const pCount = document.getElementById('tab-count-projects');
  if (pCount && appData.projects) pCount.innerText = appData.projects.length;

  const mCount = document.getElementById('tab-count-milestones');
  if (mCount && appData.milestones) mCount.innerText = appData.milestones.length;
}

/**
 * 10. Profile Modulation
 */
function populateProfileForm() {
  const p = appData.personal || fallbackData.personal;
  const setVal = (id, val) => {
    const el = document.getElementById(id);
    if (el) el.value = val || '';
  };

  setVal('admin-input-name', p.name);
  setVal('admin-input-location', p.location);
  setVal('admin-input-title', p.title);
  setVal('admin-input-subtitle', p.subtitle);
  setVal('admin-input-bio', p.bio);
  setVal('admin-input-avatar', p.avatar);
  setVal('admin-input-email', p.email);
  setVal('admin-input-linkedin', p.linkedin);
  setVal('admin-input-github', p.github);
  setVal('admin-input-instagram', p.instagram);
  setVal('admin-input-facebook', p.facebook);
  setVal('admin-input-twitter', p.twitter);
  setVal('admin-input-youtube', p.youtube);
  setVal('admin-input-whatsapp', p.whatsapp);
  setVal('admin-input-telegram', p.telegram);

  const img = document.getElementById('admin-avatar-preview');
  if (img) img.src = p.avatar || '';
}

function previewAvatarUrl(url) {
  const img = document.getElementById('admin-avatar-preview');
  if (img) img.src = url || '';
}

function saveProfileForm(e) {
  if (e) e.preventDefault();
  const getVal = (id) => {
    const el = document.getElementById(id);
    return el ? el.value.trim() : '';
  };

  appData.personal = {
    ...appData.personal,
    name: getVal('admin-input-name'),
    location: getVal('admin-input-location'),
    title: getVal('admin-input-title'),
    subtitle: getVal('admin-input-subtitle'),
    bio: getVal('admin-input-bio'),
    avatar: getVal('admin-input-avatar'),
    email: getVal('admin-input-email'),
    linkedin: getVal('admin-input-linkedin'),
    github: getVal('admin-input-github'),
    instagram: getVal('admin-input-instagram'),
    facebook: getVal('admin-input-facebook'),
    twitter: getVal('admin-input-twitter'),
    youtube: getVal('admin-input-youtube'),
    whatsapp: getVal('admin-input-whatsapp'),
    telegram: getVal('admin-input-telegram')
  };

  saveAppData('Profile details updated');
}

/**
 * 11. Projects Modulation
 */
function populateAdminProjectsList() {
  const container = document.getElementById('admin-projects-list');
  if (!container || !appData.projects) return;

  container.innerHTML = sanitizeHtml(appData.projects.map((p, idx) => `
    <div class="admin-list-item">
      <div class="admin-list-item-info">
        <img src="${p.image}" class="admin-list-item-thumb" alt="${p.title}">
        <div class="admin-list-item-text">
          <span class="admin-list-item-title">${p.title}</span>
          <span class="admin-list-item-sub">${p.category} &bull; ${(p.components || []).length} components &bull; ${(p.gallery || []).length} gallery photos</span>
        </div>
      </div>
      <div class="admin-list-item-actions">
        ${idx > 0 ? `<button onclick="moveProject('${p.id}', -1)" class="admin-card-btn" title="Move Up"><i class="fa-solid fa-arrow-up"></i></button>` : ''}
        ${idx < appData.projects.length - 1 ? `<button onclick="moveProject('${p.id}', 1)" class="admin-card-btn" title="Move Down"><i class="fa-solid fa-arrow-down"></i></button>` : ''}
        <button onclick="openProjectEditModal('${p.id}')" class="admin-card-btn"><i class="fa-solid fa-pen"></i> Edit</button>
        <button onclick="deleteProject('${p.id}')" class="admin-card-btn admin-card-btn-del"><i class="fa-solid fa-trash"></i></button>
      </div>
    </div>
  `).join(''));
}

function moveProject(id, dir) {
  const idx = appData.projects.findIndex(p => p.id === id);
  if (idx < 0) return;
  const targetIdx = idx + dir;
  if (targetIdx < 0 || targetIdx >= appData.projects.length) return;

  const temp = appData.projects[idx];
  appData.projects[idx] = appData.projects[targetIdx];
  appData.projects[targetIdx] = temp;

  saveAppData('Projects reordered');
  populateAdminProjectsList();
}

function deleteProject(id) {
  const p = appData.projects.find(x => x.id === id);
  if (!p) return;
  if (!confirm(`Are you sure you want to delete project: "${p.title}"?`)) return;

  appData.projects = appData.projects.filter(x => x.id !== id);
  saveAppData(`Project "${p.title}" deleted`);
  populateAdminProjectsList();
}

function openProjectEditModal(id = null) {
  const modal = document.getElementById('project-editor-modal');
  if (!modal) return;

  const titleEl = document.getElementById('project-editor-title');
  const origIdInput = document.getElementById('edit-project-original-id');
  const titleInput = document.getElementById('edit-project-title');
  const catInput = document.getElementById('edit-project-category');
  const shortInput = document.getElementById('edit-project-short-desc');
  const fullInput = document.getElementById('edit-project-full-desc');
  const imgInput = document.getElementById('edit-project-image');
  const compsInput = document.getElementById('edit-project-components');
  const specsContainer = document.getElementById('edit-project-specs-container');
  const galleryContainer = document.getElementById('edit-project-gallery-container');
  const codeTextEl = document.getElementById('edit-project-code-text');
  const codeFileEl = document.getElementById('edit-project-code-filename');
  const codeLangEl = document.getElementById('edit-project-code-lang');

  if (specsContainer) specsContainer.innerHTML = '';
  if (galleryContainer) galleryContainer.innerHTML = '';

  if (id) {
    const p = appData.projects.find(x => x.id === id);
    if (!p) return;
    titleEl.innerText = 'Edit Project: ' + p.title;
    origIdInput.value = p.id;
    titleInput.value = p.title || '';
    catInput.value = p.category || '';
    shortInput.value = p.shortDesc || '';
    fullInput.value = p.fullDescription || '';
    imgInput.value = p.image || '';
    previewProjectImg(p.image || '');
    compsInput.value = (p.components || []).join(', ');

    // Populate Specs
    Object.entries(p.specs || {}).forEach(([k, v]) => addSpecRow(k, v));
    // Populate Gallery
    (p.gallery || []).forEach(url => addGalleryPhotoRow(url));

    // Populate Code
    if (codeTextEl) codeTextEl.value = p.code || '';
    if (codeFileEl) codeFileEl.value = p.codeFilename || '';
    if (codeLangEl) codeLangEl.value = p.codeLanguage || 'c';
  } else {
    titleEl.innerText = 'Create New Project';
    origIdInput.value = '';
    titleInput.value = '';
    catInput.value = 'Custom PCB';
    shortInput.value = '';
    fullInput.value = '';
    const defImg = 'https://lh3.googleusercontent.com/d/1foFDBz4k-Q3PTBsqhG7wjFMqwpDfS2o7';
    imgInput.value = defImg;
    previewProjectImg(defImg);
    compsInput.value = 'KiCad, STM32, Passives';

    addSpecRow('Microcontroller', 'STM32F4 Cortex-M4');
    addSpecRow('PCB Design Tool', 'KiCad');
    addGalleryPhotoRow(defImg);

    if (codeTextEl) codeTextEl.value = '';
    if (codeFileEl) codeFileEl.value = '';
    if (codeLangEl) codeLangEl.value = 'c';
  }

  updateCodeStats();
  setupProjectEditorEvents();
  modal.classList.add('active');
  document.body.style.overflow = 'hidden';
}

function closeProjectEditModal() {
  const modal = document.getElementById('project-editor-modal');
  if (modal) modal.classList.remove('active');
  const panel = document.getElementById('admin-panel-modal');
  if (!panel || !panel.classList.contains('active')) {
    document.body.style.overflow = '';
  }
}

function previewProjectImg(url) {
  const img = document.getElementById('edit-project-img-preview');
  const hint = document.getElementById('edit-project-drop-hint');
  if (img) {
    if (url && url.trim()) {
      img.src = url.trim();
      img.style.display = 'block';
      if (hint) hint.style.display = 'none';
    } else {
      img.src = '';
      img.style.display = 'none';
      if (hint) hint.style.display = 'flex';
    }
  }
}

function clearProjectImage() {
  const imgInput = document.getElementById('edit-project-image');
  if (imgInput) imgInput.value = '';
  previewProjectImg('');
  showToast('Cover image cleared');
}

/**
 * Client-side Image Compression via Canvas
 * Automatically resizes large camera photos to max 1400px and compresses to lightweight Data URLs
 */
function compressImage(file, maxWidth = 1400, quality = 0.88) {
  return new Promise((resolve, reject) => {
    if (file.type === 'image/svg+xml' || file.size < 70 * 1024) {
      const reader = new FileReader();
      reader.onload = e => resolve(e.target.result);
      reader.onerror = reject;
      reader.readAsDataURL(file);
      return;
    }

    const img = new Image();
    const objectUrl = URL.createObjectURL(file);
    img.onload = () => {
      URL.revokeObjectURL(objectUrl);
      let width = img.width;
      let height = img.height;

      if (width > maxWidth || height > maxWidth) {
        if (width > height) {
          height = Math.round((height * maxWidth) / width);
          width = maxWidth;
        } else {
          width = Math.round((width * maxWidth) / height);
          height = maxWidth;
        }
      }

      const canvas = document.createElement('canvas');
      canvas.width = width;
      canvas.height = height;
      const ctx = canvas.getContext('2d');
      ctx.drawImage(img, 0, 0, width, height);

      let mime = file.type === 'image/png' ? 'image/png' : 'image/jpeg';
      let dataUrl = canvas.toDataURL(mime, quality);
      if (mime === 'image/png' && dataUrl.length > 400 * 1024) {
        dataUrl = canvas.toDataURL('image/jpeg', 0.85);
      }
      resolve(dataUrl);
    };
    img.onerror = () => {
      URL.revokeObjectURL(objectUrl);
      const reader = new FileReader();
      reader.onload = e => resolve(e.target.result);
      reader.onerror = reject;
      reader.readAsDataURL(file);
    };
    img.src = objectUrl;
  });
}

async function handleProjectImageUpload(event) {
  const file = event.target.files && event.target.files[0];
  if (!file) return;

  if (!file.type.startsWith('image/')) {
    alert('Please select an image file (PNG, JPG, WebP, SVG).');
    return;
  }

  try {
    const dataUrl = await compressImage(file);
    const imgInput = document.getElementById('edit-project-image');
    if (imgInput) imgInput.value = dataUrl;
    previewProjectImg(dataUrl);
    showToast(`Picture "${file.name}" uploaded successfully!`);
  } catch (err) {
    console.error('Failed to process image:', err);
    alert('Failed to load image: ' + err.message);
  } finally {
    event.target.value = '';
  }
}

function addSpecRow(key = '', val = '') {
  const container = document.getElementById('edit-project-specs-container');
  if (!container) return;
  const row = document.createElement('div');
  row.className = 'admin-spec-row';
  row.innerHTML = sanitizeHtml(`
    <input type="text" class="admin-input spec-key" placeholder="Key (e.g. Microcontroller)" value="${key}">
    <input type="text" class="admin-input spec-val" placeholder="Value (e.g. ESP32-C3)" value="${val}">
    <button type="button" class="admin-row-delete-btn" onclick="this.parentElement.remove()" title="Delete Spec"><i class="fa-solid fa-trash"></i></button>
  `);
  container.appendChild(row);
}

function addGalleryPhotoRow(url = '') {
  const container = document.getElementById('edit-project-gallery-container');
  if (!container) return;
  const row = document.createElement('div');
  row.className = 'admin-gallery-row';
  row.innerHTML = sanitizeHtml(`
    <div class="gallery-row-thumb">
      ${url ? `<img src="${url}" alt="Thumbnail">` : `<i class="fa-solid fa-image"></i>`}
    </div>
    <input type="text" class="admin-input gallery-url" placeholder="https://... or uploaded image" value="${url}" oninput="updateGalleryRowThumb(this)">
    <label class="gallery-upload-icon-btn" title="Upload image for this slot">
      <i class="fa-solid fa-cloud-arrow-up"></i>
      <input type="file" accept="image/*" style="display:none;" onchange="handleSingleGalleryRowUpload(event, this)">
    </label>
    <button type="button" class="admin-row-delete-btn" onclick="this.parentElement.remove()" title="Delete Photo"><i class="fa-solid fa-trash"></i></button>
  `);
  container.appendChild(row);
}

function updateGalleryRowThumb(input) {
  const row = input.closest('.admin-gallery-row');
  if (!row) return;
  const thumb = row.querySelector('.gallery-row-thumb');
  if (!thumb) return;
  const val = input.value.trim();
  if (val) {
    thumb.innerHTML = sanitizeHtml(`<img src="${val}" alt="Thumbnail">`);
  } else {
    thumb.innerHTML = sanitizeHtml(`<i class="fa-solid fa-image"></i>`);
  }
}

async function handleSingleGalleryRowUpload(event, btn) {
  const file = event.target.files && event.target.files[0];
  if (!file) return;
  try {
    const dataUrl = await compressImage(file, 1200, 0.85);
    const row = btn.closest('.admin-gallery-row');
    if (row) {
      const input = row.querySelector('.gallery-url');
      if (input) {
        input.value = dataUrl;
        updateGalleryRowThumb(input);
      }
    }
    showToast(`Photo "${file.name}" uploaded to gallery!`);
  } catch (err) {
    alert('Failed to upload image: ' + err.message);
  } finally {
    event.target.value = '';
  }
}

async function handleGalleryImagesUpload(event) {
  const files = event.target.files;
  if (!files || files.length === 0) return;
  let count = 0;
  for (const file of Array.from(files)) {
    if (!file.type.startsWith('image/')) continue;
    try {
      const dataUrl = await compressImage(file, 1200, 0.85);
      addGalleryPhotoRow(dataUrl);
      count++;
    } catch (err) {
      console.error('Gallery image compression failed', err);
    }
  }
  if (count > 0) {
    showToast(`${count} gallery photo${count > 1 ? 's' : ''} uploaded!`);
  }
  event.target.value = '';
}

function handleProjectCodeFileUpload(event) {
  const file = event.target.files && event.target.files[0];
  if (!file) return;

  const reader = new FileReader();
  reader.onload = function(e) {
    const text = e.target.result;
    const codeTextEl = document.getElementById('edit-project-code-text');
    const codeFilenameEl = document.getElementById('edit-project-code-filename');
    const codeLangEl = document.getElementById('edit-project-code-lang');

    if (codeTextEl) codeTextEl.value = text;
    if (codeFilenameEl) codeFilenameEl.value = file.name;

    const ext = file.name.split('.').pop().toLowerCase();
    let detected = 'c';
    if (['c', 'cpp', 'cc', 'cxx', 'h', 'hpp'].includes(ext)) detected = 'c';
    else if (['py', 'pyw'].includes(ext)) detected = 'python';
    else if (['ino'].includes(ext)) detected = 'arduino';
    else if (['rs'].includes(ext)) detected = 'rust';
    else if (['v', 'sv', 'vhdl', 'vhd'].includes(ext)) detected = 'verilog';
    else if (['sh', 'bash', 'zsh'].includes(ext)) detected = 'bash';
    else if (['json'].includes(ext)) detected = 'json';
    else if (['kicad_pcb', 'kicad_sch', 'kicad_pro', 'kicad_sym', 'net'].includes(ext)) detected = 'kicad';
    else if (['txt', 'md'].includes(ext)) detected = 'plaintext';

    if (codeLangEl) codeLangEl.value = detected;
    updateCodeStats();
    showToast(`Code loaded from "${file.name}"!`);
  };
  reader.readAsText(file);
  event.target.value = '';
}

function clearProjectCode() {
  const codeTextEl = document.getElementById('edit-project-code-text');
  const codeFilenameEl = document.getElementById('edit-project-code-filename');
  if (codeTextEl) codeTextEl.value = '';
  if (codeFilenameEl) codeFilenameEl.value = '';
  updateCodeStats();
  showToast('Project code cleared');
}

function updateCodeStats() {
  const codeTextEl = document.getElementById('edit-project-code-text');
  const statsEl = document.getElementById('edit-project-code-stats');
  if (!codeTextEl || !statsEl) return;
  const val = codeTextEl.value;
  if (!val.trim()) {
    statsEl.innerText = '0 lines';
    return;
  }
  const lines = val.split('\n').length;
  statsEl.innerText = `${lines} line${lines > 1 ? 's' : ''} • ${val.length} chars`;
}

function copyProjectCode(btn) {
  const codeEl = document.getElementById('modal-code-content');
  if (!codeEl) return;
  const text = codeEl.textContent;
  navigator.clipboard.writeText(text).then(() => {
    if (btn) {
      const origHtml = btn.innerHTML;
      btn.innerHTML = sanitizeHtml(`<i class="fa-solid fa-check"></i> <span class="copy-text">Copied!</span>`);
      btn.classList.add('btn-copied');
      setTimeout(() => {
        btn.innerHTML = sanitizeHtml(origHtml);
        btn.classList.remove('btn-copied');
      }, 2000);
    }
    showToast('Code copied to clipboard!');
  }).catch(() => {
    const ta = document.createElement('textarea');
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
    showToast('Code copied to clipboard!');
  });
}

function setupProjectEditorEvents() {
  const codeTextEl = document.getElementById('edit-project-code-text');
  if (codeTextEl && !codeTextEl.dataset.eventsBound) {
    codeTextEl.dataset.eventsBound = 'true';
    codeTextEl.addEventListener('keydown', function(e) {
      if (e.key === 'Tab') {
        e.preventDefault();
        const start = this.selectionStart;
        const end = this.selectionEnd;
        this.value = this.value.substring(0, start) + '  ' + this.value.substring(end);
        this.selectionStart = this.selectionEnd = start + 2;
        updateCodeStats();
      }
    });

    // Drag & drop code file onto textarea
    codeTextEl.addEventListener('dragover', function(e) {
      e.preventDefault();
      this.style.borderColor = 'var(--accent-primary)';
    });
    codeTextEl.addEventListener('dragleave', function(e) {
      e.preventDefault();
      this.style.borderColor = '';
    });
    codeTextEl.addEventListener('drop', function(e) {
      e.preventDefault();
      this.style.borderColor = '';
      const file = e.dataTransfer.files && e.dataTransfer.files[0];
      if (!file) return;
      handleProjectCodeFileUpload({ target: { files: [file], value: '' } });
    });
  }

  // Drag & drop image onto cover dropzone
  const dropzone = document.getElementById('edit-project-dropzone');
  if (dropzone && !dropzone.dataset.eventsBound) {
    dropzone.dataset.eventsBound = 'true';
    dropzone.addEventListener('dragover', function(e) {
      e.preventDefault();
      this.classList.add('drag-active');
    });
    dropzone.addEventListener('dragleave', function(e) {
      e.preventDefault();
      this.classList.remove('drag-active');
    });
    dropzone.addEventListener('drop', function(e) {
      e.preventDefault();
      this.classList.remove('drag-active');
      const file = e.dataTransfer.files && e.dataTransfer.files[0];
      if (!file) return;
      handleProjectImageUpload({ target: { files: [file], value: '' } });
    });
  }
}

function handleSaveProject(e) {
  if (e) e.preventDefault();
  const origId = document.getElementById('edit-project-original-id').value;
  const title = document.getElementById('edit-project-title').value.trim();
  const category = document.getElementById('edit-project-category').value.trim();
  const shortDesc = document.getElementById('edit-project-short-desc').value.trim();
  const fullDescription = document.getElementById('edit-project-full-desc').value.trim();
  const image = document.getElementById('edit-project-image').value.trim();
  const code = document.getElementById('edit-project-code-text') ? document.getElementById('edit-project-code-text').value : '';
  const codeFilename = document.getElementById('edit-project-code-filename') ? document.getElementById('edit-project-code-filename').value.trim() : '';
  const codeLanguage = document.getElementById('edit-project-code-lang') ? document.getElementById('edit-project-code-lang').value : 'c';

  const components = document.getElementById('edit-project-components').value
    .split(',')
    .map(c => c.trim())
    .filter(Boolean);

  // Specs
  const specs = {};
  document.querySelectorAll('#edit-project-specs-container .admin-spec-row').forEach(row => {
    const k = row.querySelector('.spec-key').value.trim();
    const v = row.querySelector('.spec-val').value.trim();
    if (k) specs[k] = v;
  });

  // Gallery
  const gallery = [];
  document.querySelectorAll('#edit-project-gallery-container .gallery-url').forEach(input => {
    const val = input.value.trim();
    if (val) gallery.push(val);
  });
  if (gallery.length === 0 && image) {
    gallery.push(image);
  }

  const projId = origId || title.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '') || `proj-${Date.now()}`;

  const projectObj = {
    id: projId,
    title,
    category,
    shortDesc,
    fullDescription,
    image,
    specs,
    components,
    gallery,
    code,
    codeFilename: codeFilename || (code.trim() ? 'main.c' : ''),
    codeLanguage: codeLanguage || 'c'
  };

  if (origId) {
    const idx = appData.projects.findIndex(x => x.id === origId);
    if (idx >= 0) {
      appData.projects[idx] = projectObj;
    } else {
      appData.projects.push(projectObj);
    }
  } else {
    appData.projects.unshift(projectObj);
  }

  closeProjectEditModal();
  saveAppData(`Project "${title}" saved`);
  populateAdminProjectsList();
}

/**
 * 12. Skills Modulation
 */
function populateAdminSkillsList() {
  const container = document.getElementById('admin-skills-list');
  if (!container || !appData.skills) return;

  container.innerHTML = sanitizeHtml(appData.skills.map((cat, catIdx) => `
    <div class="admin-section-block" style="margin-bottom: 0.75rem;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.65rem;">
        <div style="display: flex; align-items: center; gap: 0.5rem;">
          <input type="text" class="admin-input" style="font-weight: 700; width: 260px;" value="${cat.category}" onchange="renameSkillCategory(${catIdx}, this.value)">
        </div>
        <div style="display: flex; gap: 0.4rem;">
          <button onclick="addSkillItem(${catIdx})" class="admin-card-btn"><i class="fa-solid fa-plus"></i> Add Item</button>
          <button onclick="deleteSkillCategory(${catIdx})" class="admin-card-btn admin-card-btn-del"><i class="fa-solid fa-trash"></i></button>
        </div>
      </div>
      <div style="display: flex; flex-wrap: wrap; gap: 0.45rem;">
        ${cat.items.map((item, itemIdx) => `
          <span class="tech-chip" style="display: inline-flex; align-items: center; gap: 0.4rem;">
            ${item}
            <button onclick="removeSkillItem(${catIdx}, ${itemIdx})" style="color: #ef4444; font-size: 0.75rem;"><i class="fa-solid fa-xmark"></i></button>
          </span>
        `).join('')}
      </div>
    </div>
  `).join(''));
}

function addNewSkillCategory() {
  const name = prompt('Enter new Skill Domain Category name:');
  if (!name || !name.trim()) return;
  appData.skills.push({
    category: name.trim(),
    items: ['Core Skill 1', 'Core Skill 2']
  });
  saveAppData(`Added domain "${name}"`);
  populateAdminSkillsList();
}

function renameSkillCategory(idx, newName) {
  if (!newName || !newName.trim()) return;
  appData.skills[idx].category = newName.trim();
  saveAppData('Domain renamed');
}

function deleteSkillCategory(catIdx) {
  const cat = appData.skills[catIdx];
  if (!confirm(`Delete domain category "${cat.category}"?`)) return;
  appData.skills.splice(catIdx, 1);
  saveAppData(`Domain deleted`);
  populateAdminSkillsList();
}

function addSkillItem(catIdx) {
  const item = prompt(`Add new skill to "${appData.skills[catIdx].category}":`);
  if (!item || !item.trim()) return;
  appData.skills[catIdx].items.push(item.trim());
  saveAppData(`Added "${item}"`);
  populateAdminSkillsList();
}

function removeSkillItem(catIdx, itemIdx) {
  appData.skills[catIdx].items.splice(itemIdx, 1);
  saveAppData('Skill removed');
  populateAdminSkillsList();
}

/**
 * 13. Milestones Modulation
 */
function populateAdminMilestonesList() {
  const container = document.getElementById('admin-milestones-list');
  if (!container || !appData.milestones) return;

  container.innerHTML = sanitizeHtml(appData.milestones.map((m, idx) => `
    <div class="admin-list-item" draggable="true"
         data-index="${idx}"
         ondragstart="handleMilestoneDragStart(event, ${idx})"
         ondragover="handleMilestoneDragOver(event, ${idx})"
         ondragleave="handleMilestoneDragLeave(event, ${idx})"
         ondrop="handleMilestoneDrop(event, ${idx})"
         ondragend="handleMilestoneDragEnd(event)">
      <div class="admin-list-item-info">
        <span class="admin-drag-handle" title="Drag to reorder"><i class="fa-solid fa-grip-vertical"></i></span>
        <div class="admin-list-item-text">
          <span class="admin-list-item-title">${m.title}</span>
          <span class="admin-list-item-sub">[${m.year}] &bull; ${m.issuer} &bull; <strong style="color: var(--accent-primary); font-family: var(--font-mono);">#${idx + 1}</strong></span>
        </div>
      </div>
      <div class="admin-list-item-actions">
        <button type="button" onclick="moveMilestone(${idx}, -1)" ${idx === 0 ? 'disabled' : ''} class="admin-card-btn" title="Move milestone up"><i class="fa-solid fa-arrow-up"></i></button>
        <button type="button" onclick="moveMilestone(${idx}, 1)" ${idx === appData.milestones.length - 1 ? 'disabled' : ''} class="admin-card-btn" title="Move milestone down"><i class="fa-solid fa-arrow-down"></i></button>
        <button type="button" onclick="openMilestoneEditModal(${idx})" class="admin-card-btn"><i class="fa-solid fa-pen"></i> Edit</button>
        <button type="button" onclick="deleteMilestone(${idx})" class="admin-card-btn admin-card-btn-del" title="Delete milestone"><i class="fa-solid fa-trash"></i></button>
      </div>
    </div>
  `).join(''));
}

function openMilestoneEditModal(idx = null) {
  const modal = document.getElementById('milestone-editor-modal');
  if (!modal) return;

  const idxInput = document.getElementById('edit-milestone-index');
  const yearInput = document.getElementById('edit-milestone-year');
  const issuerInput = document.getElementById('edit-milestone-issuer');
  const titleInput = document.getElementById('edit-milestone-title');
  const descInput = document.getElementById('edit-milestone-desc');

  if (idx !== null && idx !== undefined) {
    const m = appData.milestones[idx];
    idxInput.value = idx;
    yearInput.value = m.year || '';
    issuerInput.value = m.issuer || '';
    titleInput.value = m.title || '';
    descInput.value = m.description || '';
  } else {
    idxInput.value = '';
    yearInput.value = '2025';
    issuerInput.value = '';
    titleInput.value = '';
    descInput.value = '';
  }

  modal.classList.add('active');
  document.body.style.overflow = 'hidden';
}

function closeMilestoneEditModal() {
  const modal = document.getElementById('milestone-editor-modal');
  if (modal) modal.classList.remove('active');
  const panel = document.getElementById('admin-panel-modal');
  if (!panel || !panel.classList.contains('active')) {
    document.body.style.overflow = '';
  }
}

function handleSaveMilestone(e) {
  if (e) e.preventDefault();
  const idx = document.getElementById('edit-milestone-index').value;
  const milestoneObj = {
    year: document.getElementById('edit-milestone-year').value.trim(),
    issuer: document.getElementById('edit-milestone-issuer').value.trim(),
    title: document.getElementById('edit-milestone-title').value.trim(),
    description: document.getElementById('edit-milestone-desc').value.trim()
  };

  if (idx !== '') {
    appData.milestones[parseInt(idx, 10)] = milestoneObj;
  } else {
    appData.milestones.push(milestoneObj);
  }

  closeMilestoneEditModal();
  saveAppData(`Milestone "${milestoneObj.title}" saved`);
  populateAdminMilestonesList();
}

function deleteMilestone(idx) {
  const m = appData.milestones[idx];
  if (!confirm(`Delete milestone: "${m.title}"?`)) return;
  appData.milestones.splice(idx, 1);
  saveAppData('Milestone deleted');
  populateAdminMilestonesList();
}

/**
 * 14. Pre-Uploaded PDF Resume Management
 */
function populateAdminResume() {
  const currentUrl = getResumePdfUrl();
  const urlInput = document.getElementById('admin-resume-url-input');
  if (urlInput) {
    urlInput.value = currentUrl.startsWith('data:') ? (localStorage.getItem('portfolio_custom_resume_pdf_name') || 'custom_uploaded.pdf') : currentUrl;
  }

  const activeName = document.getElementById('admin-pdf-active-name');
  if (activeName) {
    if (localStorage.getItem('portfolio_custom_resume_pdf')) {
      activeName.innerText = localStorage.getItem('portfolio_custom_resume_pdf_name') || 'Custom Uploaded PDF Resume';
    } else {
      activeName.innerText = (appData && appData.resumeUrl) || 'resume.pdf';
    }
  }

  const customBadge = document.getElementById('admin-pdf-custom-badge');
  if (customBadge) {
    customBadge.style.display = localStorage.getItem('portfolio_custom_resume_pdf') ? 'block' : 'none';
  }

  const previewFrame = document.getElementById('admin-resume-preview-frame');
  if (previewFrame) {
    previewFrame.src = currentUrl;
  }
}

function handleAdminPdfUpload(event) {
  const file = event.target.files && event.target.files[0];
  if (!file) return;

  if (file.type !== 'application/pdf' && !file.name.toLowerCase().endsWith('.pdf')) {
    alert('Please select a valid PDF (.pdf) file.');
    return;
  }

  if (file.size > 15 * 1024 * 1024) {
    alert('File size exceeds 15MB. Please place large PDF files directly into public/resume.pdf.');
    return;
  }

  const reader = new FileReader();
  reader.onload = function (e) {
    try {
      const dataUrl = e.target.result;
      localStorage.setItem('portfolio_custom_resume_pdf', dataUrl);
      localStorage.setItem('portfolio_custom_resume_pdf_name', file.name);
      if (appData) appData.resumeUrl = dataUrl;
      populateAdminResume();
      setupResumeModal();
      showToast(`Resume PDF "${file.name}" uploaded successfully!`);
    } catch (err) {
      alert('Could not save PDF to browser storage: ' + err.message);
    }
  };
  reader.readAsDataURL(file);
}

function resetResumePdfToDefault() {
  localStorage.removeItem('portfolio_custom_resume_pdf');
  localStorage.removeItem('portfolio_custom_resume_pdf_name');
  if (appData) appData.resumeUrl = 'resume.pdf';
  populateAdminResume();
  setupResumeModal();
  showToast('Reset to default resume.pdf');
}

function saveAdminPdfUrl() {
  const input = document.getElementById('admin-resume-url-input');
  if (!input) return;
  const val = input.value.trim();
  if (!val) {
    alert('Please enter a valid URL or path (e.g., resume.pdf).');
    return;
  }
  localStorage.removeItem('portfolio_custom_resume_pdf');
  localStorage.removeItem('portfolio_custom_resume_pdf_name');
  if (!appData) appData = {};
  appData.resumeUrl = val;
  saveAppData('Resume PDF URL updated');
  populateAdminResume();
  setupResumeModal();
  showToast('Resume PDF URL updated');
}

function testOpenCurrentPdf() {
  const url = getResumePdfUrl();
  window.open(url, '_blank', 'noopener,noreferrer');
}

function downloadCurrentPdf() {
  const url = getResumePdfUrl();
  const filename = (appData && appData.resumeFilename) || 'Mohammed_Moulay_Lekbir_Resume.pdf';
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
}

function saveResumeSummary() {
  saveAppData('Resume updated');
}

// Experience
function openExperienceEditModal(idx = null) {
  const modal = document.getElementById('experience-editor-modal');
  if (!modal) return;
  const idxInput = document.getElementById('edit-exp-index');
  const roleInput = document.getElementById('edit-exp-role');
  const periodInput = document.getElementById('edit-exp-period');
  const orgInput = document.getElementById('edit-exp-org');
  const bulletsInput = document.getElementById('edit-exp-bullets');

  if (idx !== null && idx !== undefined) {
    const exp = appData.resumeData.experience[idx];
    idxInput.value = idx;
    roleInput.value = exp.role || '';
    periodInput.value = exp.period || '';
    orgInput.value = exp.organization || '';
    bulletsInput.value = (exp.bulletPoints || []).join('\n');
  } else {
    idxInput.value = '';
    roleInput.value = '';
    periodInput.value = '2024 - Present';
    orgInput.value = '';
    bulletsInput.value = '';
  }

  modal.classList.add('active');
  document.body.style.overflow = 'hidden';
}

function closeExperienceEditModal() {
  const modal = document.getElementById('experience-editor-modal');
  if (modal) modal.classList.remove('active');
  const panel = document.getElementById('admin-panel-modal');
  if (!panel || !panel.classList.contains('active')) {
    document.body.style.overflow = '';
  }
}

function handleSaveExperience(e) {
  if (e) e.preventDefault();
  if (!appData.resumeData) appData.resumeData = {};
  if (!appData.resumeData.experience) appData.resumeData.experience = [];

  const idx = document.getElementById('edit-exp-index').value;
  const expObj = {
    role: document.getElementById('edit-exp-role').value.trim(),
    period: document.getElementById('edit-exp-period').value.trim(),
    organization: document.getElementById('edit-exp-org').value.trim(),
    bulletPoints: document.getElementById('edit-exp-bullets').value.split('\n').map(b => b.trim()).filter(Boolean)
  };

  if (idx !== '') {
    appData.resumeData.experience[parseInt(idx, 10)] = expObj;
  } else {
    appData.resumeData.experience.push(expObj);
  }

  closeExperienceEditModal();
  saveAppData(`Experience "${expObj.role}" saved`);
  populateAdminResume();
}

function deleteExperience(idx) {
  if (!confirm(`Delete experience: "${appData.resumeData.experience[idx].role}"?`)) return;
  appData.resumeData.experience.splice(idx, 1);
  saveAppData('Experience record deleted');
  populateAdminResume();
}

// Education
function openEducationEditModal(idx = null) {
  const modal = document.getElementById('education-editor-modal');
  if (!modal) return;
  const idxInput = document.getElementById('edit-edu-index');
  const degInput = document.getElementById('edit-edu-degree');
  const periodInput = document.getElementById('edit-edu-period');
  const instInput = document.getElementById('edit-edu-inst');
  const detailsInput = document.getElementById('edit-edu-details');

  if (idx !== null && idx !== undefined) {
    const edu = appData.resumeData.education[idx];
    idxInput.value = idx;
    degInput.value = edu.degree || '';
    periodInput.value = edu.period || '';
    instInput.value = edu.institution || '';
    detailsInput.value = edu.details || '';
  } else {
    idxInput.value = '';
    degInput.value = '';
    periodInput.value = '';
    instInput.value = '';
    detailsInput.value = '';
  }

  modal.classList.add('active');
  document.body.style.overflow = 'hidden';
}

function closeEducationEditModal() {
  const modal = document.getElementById('education-editor-modal');
  if (modal) modal.classList.remove('active');
  const panel = document.getElementById('admin-panel-modal');
  if (!panel || !panel.classList.contains('active')) {
    document.body.style.overflow = '';
  }
}

function handleSaveEducation(e) {
  if (e) e.preventDefault();
  if (!appData.resumeData) appData.resumeData = {};
  if (!appData.resumeData.education) appData.resumeData.education = [];

  const idx = document.getElementById('edit-edu-index').value;
  const eduObj = {
    degree: document.getElementById('edit-edu-degree').value.trim(),
    period: document.getElementById('edit-edu-period').value.trim(),
    institution: document.getElementById('edit-edu-inst').value.trim(),
    details: document.getElementById('edit-edu-details').value.trim()
  };

  if (idx !== '') {
    appData.resumeData.education[parseInt(idx, 10)] = eduObj;
  } else {
    appData.resumeData.education.push(eduObj);
  }

  closeEducationEditModal();
  saveAppData(`Education "${eduObj.degree}" saved`);
  populateAdminResume();
}

function deleteEducation(idx) {
  if (!confirm(`Delete education record: "${appData.resumeData.education[idx].degree}"?`)) return;
  appData.resumeData.education.splice(idx, 1);
  saveAppData('Education record deleted');
  populateAdminResume();
}

/**
 * 15. Security & Data Backup / Export
 */
function populateAdminSecurityInfo() {
  const activeHash = getActiveAdminPasswordHash();
  const source = getActivePasswordSource();
  const isDefault = (activeHash === DEFAULT_ADMIN_PASS_HASH);

  const badgeWrap = document.getElementById('admin-security-status-badge-wrap');
  if (badgeWrap) {
    badgeWrap.innerHTML = isDefault
      ? `<span id="admin-security-status-badge" class="admin-status-badge badge-warning"><i class="fa-solid fa-triangle-exclamation"></i> Default Password</span>`
      : `<span id="admin-security-status-badge" class="admin-status-badge badge-success"><i class="fa-solid fa-circle-check"></i> Custom Password</span>`;
  }

  const srcEl = document.getElementById('admin-security-source');
  if (srcEl) {
    srcEl.innerText = source;
  }

  const hashEl = document.getElementById('admin-security-hash-preview');
  if (hashEl) {
    hashEl.innerText = activeHash ? `${activeHash.substring(0, 8)}...${activeHash.substring(activeHash.length - 8)}` : 'None';
    hashEl.title = activeHash || '';
  }
}

async function handlePasswordChange(e) {
  if (e) e.preventDefault();
  const currPass = (document.getElementById('admin-curr-pass')?.value || '');
  const newPass = (document.getElementById('admin-new-pass')?.value || '');
  const confirmPass = (document.getElementById('admin-confirm-pass')?.value || '');

  const activeHash = getActiveAdminPasswordHash();
  const currHash = await hashStringSHA256(currPass);

  const isCurrValid = (
    currHash === activeHash ||
    currPass === activeHash ||
    (activeHash === DEFAULT_ADMIN_PASS_HASH && currPass === 'admin123')
  );

  if (!isCurrValid) {
    alert('Incorrect current password.');
    return;
  }
  if (!newPass || newPass.length < 6) {
    alert('New password must be at least 6 characters.');
    return;
  }
  if (confirmPass && newPass !== confirmPass) {
    alert('New passwords do not match. Please verify and re-type.');
    return;
  }

  const newHash = await hashStringSHA256(newPass);

  // 1. Update current device's local storage
  localStorage.setItem(ADMIN_PASS_KEY, newHash);

  // 2. Persist in central appData for cross-device dataset export
  if (!appData) {
    appData = JSON.parse(JSON.stringify(fallbackData));
  }
  appData.adminPasswordHash = newHash;
  saveAppData('Admin password securely updated');

  // 3. Clear inputs
  if (document.getElementById('admin-curr-pass')) document.getElementById('admin-curr-pass').value = '';
  if (document.getElementById('admin-new-pass')) document.getElementById('admin-new-pass').value = '';
  if (document.getElementById('admin-confirm-pass')) document.getElementById('admin-confirm-pass').value = '';

  // 4. Update UI & Display cross-device sync guide alert
  populateAdminSecurityInfo();
  const alertEl = document.getElementById('admin-sync-success-alert');
  if (alertEl) {
    alertEl.style.display = 'block';
    alertEl.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  showToast('Admin password updated! Follow the sync guide to apply to other devices.');
}

function copyViteEnvSnippet() {
  const hash = getActiveAdminPasswordHash();
  const snippet = `VITE_ADMIN_PASS_HASH=${hash}`;
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(snippet).then(() => {
      showToast('Copied VITE_ADMIN_PASS_HASH to clipboard');
    }).catch(() => {
      prompt('Copy your Vercel Environment Variable:', snippet);
    });
  } else {
    prompt('Copy your Vercel Environment Variable:', snippet);
  }
}

function copyActiveHash() {
  const hash = getActiveAdminPasswordHash();
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(hash).then(() => {
      showToast('SHA-256 hash copied to clipboard');
    }).catch(() => {
      prompt('Copy your SHA-256 Hash:', hash);
    });
  } else {
    prompt('Copy your SHA-256 Hash:', hash);
  }
}

function exportDataJson() {
  if (!appData) {
    appData = JSON.parse(JSON.stringify(fallbackData));
  }
  // Guarantee active admin password hash is embedded into exported JSON
  const activeHash = getActiveAdminPasswordHash();
  if (activeHash) {
    appData.adminPasswordHash = activeHash;
  }
  const jsonStr = JSON.stringify(appData, null, 2);
  const blob = new Blob([jsonStr], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'data.json';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  showToast('data.json downloaded (with cross-device password hash)');
}

function copyDataJson() {
  if (!appData) {
    appData = JSON.parse(JSON.stringify(fallbackData));
  }
  const activeHash = getActiveAdminPasswordHash();
  if (activeHash) {
    appData.adminPasswordHash = activeHash;
  }
  const jsonStr = JSON.stringify(appData, null, 2);
  navigator.clipboard.writeText(jsonStr).then(() => {
    showToast('Complete JSON copied to clipboard');
  }).catch(() => {
    showToast('Failed to copy to clipboard');
  });
}

function importDataJsonFile(e) {
  const file = e.target.files && e.target.files[0];
  if (!file) return;

  const reader = new FileReader();
  reader.onload = function (evt) {
    try {
      const rawParsed = JSON.parse(evt.target.result);
      const parsed = sanitizeDataSchema(rawParsed);
      if (parsed && parsed.personal && parsed.projects) {
        appData = parsed;
        if (parsed.adminPasswordHash && typeof parsed.adminPasswordHash === 'string') {
          localStorage.setItem(ADMIN_PASS_KEY, parsed.adminPasswordHash.trim());
        }
        saveAppData('Imported custom dataset successfully');
        populateAdminSecurityInfo();
        openAdminControlPanel('profile');
      } else {
        alert('Invalid data.json schema. Required "personal" and "projects" objects.');
      }
    } catch (err) {
      alert('Could not parse JSON file: ' + err.message);
    }
  };
  reader.readAsText(file);
}

function openJsonPasteModal() {
  const modal = document.getElementById('json-paste-modal');
  if (modal) {
    if (!appData) appData = JSON.parse(JSON.stringify(fallbackData));
    const activeHash = getActiveAdminPasswordHash();
    if (activeHash) appData.adminPasswordHash = activeHash;
    document.getElementById('raw-json-paste-textarea').value = JSON.stringify(appData, null, 2);
    modal.classList.add('active');
    document.body.style.overflow = 'hidden';
  }
}

function closeJsonPasteModal() {
  const modal = document.getElementById('json-paste-modal');
  if (modal) modal.classList.remove('active');
  const panel = document.getElementById('admin-panel-modal');
  if (!panel || !panel.classList.contains('active')) {
    document.body.style.overflow = '';
  }
}

function applyPastedJson() {
  const raw = document.getElementById('raw-json-paste-textarea').value;
  try {
    const rawParsed = JSON.parse(raw);
    const parsed = sanitizeDataSchema(rawParsed);
    if (parsed && parsed.personal && parsed.projects) {
      appData = parsed;
      if (parsed.adminPasswordHash && typeof parsed.adminPasswordHash === 'string') {
        localStorage.setItem(ADMIN_PASS_KEY, parsed.adminPasswordHash.trim());
      }
      closeJsonPasteModal();
      saveAppData('Applied raw JSON dataset');
      populateAdminSecurityInfo();
      openAdminControlPanel('profile');
    } else {
      alert('Invalid structure. Must contain "personal" and "projects".');
    }
  } catch (err) {
    alert('Invalid JSON syntax: ' + err.message);
  }
}

function resetToDefaultData() {
  if (!confirm('Are you sure you want to reset all modifications? This will erase all custom changes in your browser and reload the factory default portfolio.')) return;
  localStorage.removeItem(STORAGE_KEY);
  localStorage.removeItem(ADMIN_PASS_KEY);
  appData = JSON.parse(JSON.stringify(fallbackData));
  saveAppData('Reset to factory default portfolio');
  populateAdminSecurityInfo();
  openAdminControlPanel('profile');
}

/**
 * 16. Navigation & Utilities
 */
function initNavigation() {
  const toggleBtn = document.getElementById('mobile-menu-toggle');
  const drawer = document.getElementById('mobile-drawer');

  if (toggleBtn && drawer) {
    toggleBtn.addEventListener('click', () => {
      const isOpen = drawer.classList.contains('open');
      drawer.classList.toggle('open', !isOpen);
      toggleBtn.innerHTML = sanitizeHtml(isOpen ? '<i class="fa-solid fa-bars"></i>' : '<i class="fa-solid fa-xmark"></i>');
    });

    drawer.querySelectorAll('a').forEach(link => {
      link.addEventListener('click', () => {
        drawer.classList.remove('open');
        toggleBtn.innerHTML = sanitizeHtml('<i class="fa-solid fa-bars"></i>');
      });
    });
  }

  const sections = document.querySelectorAll('section[id], footer[id], #contact');
  const navLinks = document.querySelectorAll('.nav-link');

  function updateActiveNavLink() {
    const scrollPosition = window.scrollY;
    const windowHeight = window.innerHeight;
    const documentHeight = Math.max(
      document.body.scrollHeight,
      document.documentElement.scrollHeight,
      document.body.offsetHeight,
      document.documentElement.offsetHeight
    );
    let current = '';

    // If user has scrolled to the bottom of the page, activate contact
    if (windowHeight + scrollPosition >= documentHeight - 60) {
      current = 'contact';
    } else {
      sections.forEach(sec => {
        const top = sec.offsetTop - 140;
        if (scrollPosition >= top) {
          current = sec.getAttribute('id');
        }
      });
    }

    navLinks.forEach(link => {
      link.classList.toggle('active', link.getAttribute('href') === `#${current}`);
    });
  }

  window.addEventListener('scroll', updateActiveNavLink, { passive: true });
  updateActiveNavLink();

  navLinks.forEach(link => {
    link.addEventListener('click', () => {
      const href = link.getAttribute('href');
      if (href && href.startsWith('#')) {
        navLinks.forEach(l => {
          l.classList.toggle('active', l.getAttribute('href') === href);
        });
      }
    });
  });

  // Close language dropdown when clicking outside
  document.addEventListener('click', (e) => {
    const switcher = document.getElementById('lang-switcher');
    if (switcher && !switcher.contains(e.target)) {
      closeLangDropdown();
    }
  });
}

function initBackToTop() {
  const btn = document.getElementById('back-to-top');
  if (!btn) return;
  window.addEventListener('scroll', () => {
    btn.classList.toggle('visible', window.scrollY > 400);
  });
  btn.addEventListener('click', () => {
    window.scrollTo({ top: 0, behavior: 'smooth' });
  });
}

function copyEmailToClipboard() {
  const email = (appData && appData.personal && appData.personal.email) || 'aedmoulay05@gmail.com';
  navigator.clipboard.writeText(email).then(() => {
    showToast(t('copiedToast') || `Email copied: ${email}`);
  }).catch(() => {
    showToast(`Email: ${email}`);
  });
}

function showToast(message) {
  let container = document.getElementById('toast-container');
  if (!container) {
    container = document.createElement('div');
    container.id = 'toast-container';
    container.className = 'toast-container';
    document.body.appendChild(container);
  }
  const toast = document.createElement('div');
  toast.className = 'toast';
  toast.innerText = message;
  container.appendChild(toast);
  setTimeout(() => toast.remove(), 2500);
}

/**
 * Contact Form Submission Handler
 * Protected with honeypot verification, client-side input sanitization, and serverless /api/contact handling
 */
async function handleContactSubmit(e) {
  if (e) e.preventDefault();
  const form = document.getElementById('contact-direct-form');
  const statusEl = document.getElementById('contact-form-status');
  const submitBtn = document.getElementById('contact-submit-btn');
  if (!form) return;

  const honeypot = (form.querySelector('input[name="_gotcha"]') || {}).value || '';
  // Honeypot trap: if filled, abort silently (bot detected)
  if (honeypot.trim().length > 0) {
    if (statusEl) {
      statusEl.className = 'contact-status-msg success';
      statusEl.textContent = 'Message sent successfully!';
    }
    form.reset();
    return;
  }

  const nameInput = document.getElementById('contact-name');
  const emailInput = document.getElementById('contact-email');
  const subjectInput = document.getElementById('contact-subject');
  const messageInput = document.getElementById('contact-message');

  const name = (nameInput ? nameInput.value : '').trim();
  const email = (emailInput ? emailInput.value : '').trim();
  const subject = (subjectInput ? subjectInput.value : '').trim();
  const message = (messageInput ? messageInput.value : '').trim();

  // Client validation
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!name || name.length < 2) {
    if (statusEl) {
      statusEl.className = 'contact-status-msg error';
      statusEl.textContent = 'Please enter your name.';
    }
    nameInput?.focus();
    return;
  }
  if (!email || !emailRegex.test(email)) {
    if (statusEl) {
      statusEl.className = 'contact-status-msg error';
      statusEl.textContent = 'Please enter a valid email address.';
    }
    emailInput?.focus();
    return;
  }
  if (!message || message.length < 10) {
    if (statusEl) {
      statusEl.className = 'contact-status-msg error';
      statusEl.textContent = 'Message must be at least 10 characters long.';
    }
    messageInput?.focus();
    return;
  }

  // UI loading state
  if (submitBtn) {
    submitBtn.disabled = true;
    submitBtn.innerHTML = sanitizeHtml('<i class="fa-solid fa-spinner fa-spin"></i> <span>Sending...</span>');
  }
  if (statusEl) {
    statusEl.className = 'contact-status-msg';
    statusEl.textContent = 'Transmitting message securely...';
  }

  try {
    const endpoint = (typeof import.meta !== 'undefined' && import.meta.env && import.meta.env.VITE_CONTACT_API_ENDPOINT) || '/api/contact';
    const res = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: DOMPurify.sanitize(name),
        email: DOMPurify.sanitize(email),
        subject: DOMPurify.sanitize(subject),
        message: DOMPurify.sanitize(message),
        _gotcha: ''
      })
    });

    const data = await res.json().catch(() => ({}));
    if (res.ok && data.success) {
      if (statusEl) {
        statusEl.className = 'contact-status-msg success';
        statusEl.textContent = data.message || 'Thank you! Your message was sent successfully.';
      }
      form.reset();
      showToast('Message sent successfully!');
    } else {
      throw new Error(data.error || 'Server rejected submission');
    }
  } catch (err) {
    console.warn('API submission failed, initiating sanitized email client fallback:', err);
    // Fallback: sanitized mailto trigger
    const cleanTo = (appData?.personal?.email) || 'aedmoulay05@gmail.com';
    const mailtoUrl = `mailto:${encodeURIComponent(cleanTo)}?subject=${encodeURIComponent(subject || 'Portfolio Collaboration')}&body=${encodeURIComponent(`From: ${name} (${email})\n\n${message}`)}`;
    window.open(mailtoUrl, '_blank', 'noopener,noreferrer');
    if (statusEl) {
      statusEl.className = 'contact-status-msg success';
      statusEl.textContent = 'Opening your secure email client...';
    }
    showToast('Redirected to email client');
    form.reset();
  } finally {
    if (submitBtn) {
      submitBtn.disabled = false;
      submitBtn.innerHTML = sanitizeHtml('<i class="fa-solid fa-paper-plane"></i> <span>Send Message</span>');
    }
  }
}

// Global Exports to window for inline onclick/onsubmit attributes
Object.assign(window, {
  initPortfolio,
  toggleTheme,
  applyTheme,
  setLanguage,
  toggleLangDropdown,
  closeLangDropdown,
  openProjectModal,
  closeProjectModal,
  openLightbox,
  closeLightbox,
  nextLightboxImage,
  prevLightboxImage,
  openResumeModal,
  closeResumeModal,
  printResume,
  copyEmailToClipboard,
  showToast,
  renderContactCards,
  moveMilestone,
  handleMilestoneDragStart,
  handleMilestoneDragOver,
  handleMilestoneDragLeave,
  handleMilestoneDrop,
  handleMilestoneDragEnd,
  handleContactSubmit,
  // Admin Methods
  openAdminAuthModal,
  closeAdminAuthModal,
  toggleAdminAuth,
  handleAdminLogin,
  logoutAdmin,
  togglePasswordVisibility,
  openAdminControlPanel,
  closeAdminControlPanel,
  switchAdminTab,
  saveProfileForm,
  previewAvatarUrl,
  openProjectEditModal,
  closeProjectEditModal,
  previewProjectImg,
  clearProjectImage,
  handleProjectImageUpload,
  addSpecRow,
  addGalleryPhotoRow,
  updateGalleryRowThumb,
  handleSingleGalleryRowUpload,
  handleGalleryImagesUpload,
  handleProjectCodeFileUpload,
  clearProjectCode,
  updateCodeStats,
  copyProjectCode,
  setupProjectEditorEvents,
  handleSaveProject,
  deleteProject,
  moveProject,
  addNewSkillCategory,
  renameSkillCategory,
  deleteSkillCategory,
  addSkillItem,
  removeSkillItem,
  openMilestoneEditModal,
  closeMilestoneEditModal,
  handleSaveMilestone,
  deleteMilestone,
  saveResumeSummary,
  openExperienceEditModal,
  closeExperienceEditModal,
  handleSaveExperience,
  deleteExperience,
  openEducationEditModal,
  closeEducationEditModal,
  handleSaveEducation,
  deleteEducation,
  handlePasswordChange,
  populateAdminSecurityInfo,
  copyViteEnvSnippet,
  copyActiveHash,
  exportDataJson,
  copyDataJson,
  importDataJsonFile,
  openJsonPasteModal,
  closeJsonPasteModal,
  applyPastedJson,
  resetToDefaultData,
  // Pre-uploaded PDF Resume Methods
  getResumePdfUrl,
  handleAdminPdfUpload,
  resetResumePdfToDefault,
  saveAdminPdfUrl,
  testOpenCurrentPdf,
  downloadCurrentPdf,
  handleSecretAdminTrigger
});

window.addEventListener('DOMContentLoaded', initPortfolio);