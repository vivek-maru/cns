let rsaKeyPair, aesKey, encryptedData, encryptedAesKey;

window.onload = async () => {
  rsaKeyPair = await window.crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256"
    },
    true,
    ["encrypt", "decrypt"]
  );
};

function ab2b64(buffer) {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}

function b642ab(base64) {
  const binary = atob(base64);
  return new Uint8Array([...binary].map(c => c.charCodeAt(0)));
}

async function startEncryption() {
  const message = document.getElementById("messageInput").value;
  if (!message) return alert("Please enter a message.");

  aesKey = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encodedMsg = new TextEncoder().encode(message);

  encryptedData = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    aesKey,
    encodedMsg
  );

  const rawAesKey = await crypto.subtle.exportKey("raw", aesKey);
  encryptedAesKey = await crypto.subtle.encrypt(
    { name: "RSA-OAEP" },
    rsaKeyPair.publicKey,
    rawAesKey
  );

  document.getElementById("encryptedKey").textContent = ab2b64(encryptedAesKey);
  document.getElementById("encryptedMessage").textContent = ab2b64(iv) + ":" + ab2b64(encryptedData);
}

async function decryptMessage() {
  const decryptedAesKeyRaw = await crypto.subtle.decrypt(
    { name: "RSA-OAEP" },
    rsaKeyPair.privateKey,
    encryptedAesKey
  );

  const aesKeyImported = await crypto.subtle.importKey(
    "raw",
    decryptedAesKeyRaw,
    { name: "AES-GCM" },
    true,
    ["encrypt", "decrypt"]
  );

  const encParts = document.getElementById("encryptedMessage").textContent.split(":");
  const iv = b642ab(encParts[0]);
  const data = b642ab(encParts[1]);

  const decryptedBuffer = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    aesKeyImported,
    data
  );

  const decryptedText = new TextDecoder().decode(decryptedBuffer);
  document.getElementById("decryptedMessage").textContent = decryptedText;
}
