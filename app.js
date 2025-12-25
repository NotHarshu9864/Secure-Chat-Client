// ============================
// Harsh Secure Chat - app.js
// ============================

const WS_URL = "https://secure-chat-1-vvo6.onrender.com"; // CHANGE THIS

// UI Elements
const messagesEl = document.querySelector(".messages");
const inputEl = document.querySelector(".msg-input");
const sendBtn = document.querySelector(".send-btn");
const statusIndicator = document.querySelector(".status-indicator");

// State
let socket;
let cryptoKeyPair;
let sharedSecret;
let aesKey;

// ----------------------------
// Utils
// ----------------------------
const encoder = new TextEncoder();
const decoder = new TextDecoder();

function setStatus(state) {
    statusIndicator.className = `status-indicator ${state}`;
}

// ----------------------------
// Crypto
// ----------------------------
async function generateKeys() {
    cryptoKeyPair = await crypto.subtle.generateKey(
        {
            name: "ECDH",
            namedCurve: "P-256",
        },
        false,
        ["deriveKey"]
    );
}

async function exportPublicKey() {
    return crypto.subtle.exportKey("raw", cryptoKeyPair.publicKey);
}

async function importPeerKey(rawKey) {
    return crypto.subtle.importKey(
        "raw",
        rawKey,
        { name: "ECDH", namedCurve: "P-256" },
        false,
        []
    );
}

async function deriveSharedKey(peerPublicKey) {
    aesKey = await crypto.subtle.deriveKey(
        {
            name: "ECDH",
            public: peerPublicKey,
        },
        cryptoKeyPair.privateKey,
        {
            name: "AES-GCM",
            length: 256,
        },
        false,
        ["encrypt", "decrypt"]
    );
}

// ----------------------------
// Encryption
// ----------------------------
async function encryptMessage(text) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        aesKey,
        encoder.encode(text)
    );

    return {
        iv: Array.from(iv),
        data: Array.from(new Uint8Array(encrypted)),
    };
}

async function decryptMessage(payload) {
    const iv = new Uint8Array(payload.iv);
    const data = new Uint8Array(payload.data);

    const decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv },
        aesKey,
        data
    );

    return decoder.decode(decrypted);
}

// ----------------------------
// WebSocket
// ----------------------------
async function connect() {
    setStatus("connecting");

    await generateKeys();
    socket = new WebSocket(WS_URL);

    socket.binaryType = "arraybuffer";

    socket.onopen = async () => {
        setStatus("online");

        const pub = await exportPublicKey();
        socket.send(
            JSON.stringify({
                type: "public-key",
                key: Array.from(new Uint8Array(pub)),
            })
        );
    };

    socket.onmessage = async (event) => {
        const msg = JSON.parse(event.data);

        if (msg.type === "public-key") {
            const peerKey = await importPeerKey(new Uint8Array(msg.key));
            await deriveSharedKey(peerKey);
            return;
        }

        if (msg.type === "message" && aesKey) {
            const text = await decryptMessage(msg.payload);
            addMessage("Harsh", text, false);
        }
    };

    socket.onclose = () => {
        setStatus("offline");
        setTimeout(connect, 2000);
    };
}

// ----------------------------
// UI
// ----------------------------
function addMessage(user, text, own) {
    const div = document.createElement("div");
    div.className = `message ${own ? "own" : "other"}`;

    div.innerHTML = `
        <div class="msg-header">${user}</div>
        <div class="msg-content">${DOMPurify.sanitize(marked.parse(text))}</div>
    `;

    messagesEl.appendChild(div);
    messagesEl.scrollTop = messagesEl.scrollHeight;

    div.querySelectorAll("pre code").forEach(block => {
        hljs.highlightElement(block);
    });
}

// ----------------------------
// Send
// ----------------------------
sendBtn.onclick = async () => {
    if (!inputEl.value || !aesKey) return;

    const text = inputEl.value;
    inputEl.value = "";

    addMessage("You", text, true);

    const payload = await encryptMessage(text);

    socket.send(
        JSON.stringify({
            type: "message",
            payload,
        })
    );
};

inputEl.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
        e.preventDefault();
        sendBtn.click();
    }
});

// ----------------------------
// Start
// ----------------------------
connect();