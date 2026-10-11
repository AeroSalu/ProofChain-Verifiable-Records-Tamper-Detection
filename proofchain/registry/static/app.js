// Show a file's SHA-256 as soon as it is chosen, before anything is uploaded.
// The server computes the fingerprint again; the two must agree for raw-bytes-v1.
const fileInput = document.querySelector("[data-fingerprint-input]");
const canonSelect = document.querySelector("[data-fingerprint-canon]");
const output = document.querySelector("[data-fingerprint-output]");

async function showFingerprint() {
  const file = fileInput.files[0];
  if (!file) {
    output.textContent = "choose a file to see it";
  } else if (canonSelect.value !== "raw-bytes-v1") {
    output.textContent = "computed by the server after the record is put in canonical form";
  } else if (!window.crypto || !crypto.subtle) {
    output.textContent = "computed by the server";
  } else {
    const digest = await crypto.subtle.digest("SHA-256", await file.arrayBuffer());
    output.textContent = Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
  }
}

if (fileInput && canonSelect && output) {
  fileInput.addEventListener("change", showFingerprint);
  canonSelect.addEventListener("change", showFingerprint);
}

// "use" buttons copy a suggestion into its field. Nothing is saved until Confirm.
document.querySelectorAll("[data-fill]").forEach((button) => {
  button.addEventListener("click", () => {
    document.getElementById(button.dataset.fill).value = button.dataset.value;
  });
});
