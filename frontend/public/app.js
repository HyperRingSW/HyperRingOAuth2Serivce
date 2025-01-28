const serverBaseURL = "http://localhost:8090";

var accessToken = localStorage.getItem("access_token") ? localStorage.getItem("access_token") : ""; // Access токен
var jwtToken = localStorage.getItem("jwt_token") ? localStorage.getItem("jwt_token") : ""; // jwt токен
var refreshToken = localStorage.getItem("refresh_token") ? localStorage.getItem("refresh_token") : "";
const redirectSignUpUrl = "/auth/signup";
const redirectSignInUrl = "/auth/signin";
var redirectURI = localStorage.getItem("redirect_uri") ? localStorage.getItem("redirect_uri") : "";

// Generate random number for PKCE
function generateCodeVerifier() {
    const array = new Uint8Array(32);
    window.crypto.getRandomValues(array);
    return arrayToBase64(array);
}

function arrayToBase64(uint8Array) {
    const binaryString = Array.from(uint8Array)
        .map((byte) => String.fromCharCode(byte))
        .join("");
    return btoa(binaryString)
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");
}

// Hash for PKCE (S256)
async function generateCodeChallenge(verifier) {
    const encoder = new TextEncoder();
    const data = encoder.encode(verifier);
    const digest = await window.crypto.subtle.digest("SHA-256", data);
    return arrayToBase64(new Uint8Array(digest));
}

// Authorization OAuth2
async function loginWithProvider(provider) {
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = await generateCodeChallenge(codeVerifier);

    // Сохраняем codeVerifier
    localStorage.setItem("pkce_code_verifier", codeVerifier);

    const redirectURL = `${serverBaseURL}/auth/redirect?provider=${provider}&redirect_uri=${encodeURIComponent(
        window.location.origin + "/callback"
    )}&code_challenge=${codeChallenge}`;

    // Редирект на OAuth2
    window.location.href = redirectURL;
}

// Processing callback
async function handleCallback() {
    const urlParams = new URLSearchParams(window.location.search);
    const code = urlParams.get("code");
    const provider = urlParams.get("state");

    const codeVerifier = localStorage.getItem("pkce_code_verifier");

    if (!code || !provider) {
        document.getElementById("response").textContent =
            "Authorization code, provider, or code_verifier not found.";
        return;
    }

    try {
        if (codeVerifier) {
            url = `${serverBaseURL}/auth/callback`
            req = {
                method: "POST",
                headers: {"Content-Type": "application/json"},
                body: JSON.stringify({
                    code: code,
                    provider: provider,
                    redirect_uri: window.location.origin + "/callback",
                    code_verifier: codeVerifier,
                })
            }
            localStorage.removeItem("pkce_code_verifier");
        } else {
            redirectURL = localStorage.getItem("redirect_uri");
            url = `${serverBaseURL}${redirectURL}`
            req = {
                method: "POST",
                headers: {"Content-Type": "application/json"},
                body: JSON.stringify({
                    code: code,
                    provider: provider,
                    redirect_uri: window.location.origin + "/callback",
                })
            }
        }

        const response = await fetch(url, req)
        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(errorText);
        }

        const data = await response.json();
        if (data.token) {
            localStorage.setItem("access_token", data.token);
        }
        if (data.jwt_token) {
            localStorage.setItem("jwt_token", data.jwt_token);
        }
        if (data.refresh_token) {
            localStorage.setItem("refresh_token", data.refresh_token);
        }

        document.getElementById("response").textContent = JSON.stringify(data);
    } catch (error) {
        document.getElementById("response").textContent = `Error: ${error.message}`;
    }
}

async function getUserProfile() {
    try {
        jwtToken = localStorage.getItem("jwt_token");
        console.log("JWT Token fetched from localStorage:", jwtToken);

        if (!jwtToken) {
            document.getElementById("response").textContent = "JWT token is missing. Please log in.";
            return;
        }

        const response = await fetch(`${serverBaseURL}/user/profile`, {
            method: "GET",
            headers: {Authorization: `Bearer ${jwtToken}`},
        });

        console.log(`${serverBaseURL}/user/profile`);
        console.log(accessToken);

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(errorText);
        }

        const data = await response.json();
        document.getElementById("response").textContent = JSON.stringify(
            data,
            null,
            2
        );
    } catch (error) {
        document.getElementById("response").textContent = `Error: ${error.message}`;
    }
}

async function backupUserData() {
    try {
        const response = await fetch(`${serverBaseURL}/user/backup`, {
            method: "GET",
            headers: {Authorization: `Bearer ${accessToken}`},
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(errorText);
        }

        const data = await response.json();
        document.getElementById("response").textContent =
            "Backup successful: " + JSON.stringify(data, null, 2);
    } catch (error) {
        document.getElementById("response").textContent = `Error: ${error.message}`;
    }
}

async function restoreUserData() {
    const backupData = prompt("Paste your backup data JSON here:");
    if (!backupData) {
        document.getElementById("response").textContent =
            "No backup data provided.";
        return;
    }

    try {
        const response = await fetch(`${serverBaseURL}/user/restore`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                Authorization: `Bearer ${accessToken}`,
            },
            body: backupData,
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(errorText);
        }

        document.getElementById("response").textContent = "Restore successful!";
    } catch (error) {
        document.getElementById("response").textContent = `Error: ${error.message}`;
    }
}

// Automatic redirect to /callback
if (window.location.pathname === "/callback") {
    handleCallback();
}


// Sign Up (uses /auth/signup)
async function signupWithProvider(provider) {
    await authenticateWithProvider(provider, redirectSignUpUrl);
}

// Sign In (uses /auth/signin)
async function signinWithProvider(provider) {
    await authenticateWithProvider(provider, redirectSignInUrl);
}

// Authenticate helper function for Sign Up/Sign In
async function authenticateWithProvider(provider, endpoint) {
    localStorage.setItem("redirect_uri", endpoint)
    const authURL = `${serverBaseURL}/auth/redirect?provider=${provider}&redirect_uri=${encodeURIComponent(
        window.location.origin + "/callback"
    )}`;
    window.location.href = authURL;
}

async function refreshTokenWithProvider(provider) {
    const refreshToken = localStorage.getItem("refresh_token");
    if (refreshToken == "") {
        document.getElementById("response").textContent = "Refresh token not found.";
        return;
    }

    try {
        const response = await fetch(`${serverBaseURL}/auth/token/refresh`, {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({refresh_token: refreshToken, provider: provider}),
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(errorText);
        }

        //const data = await response.json();
        //console.log("Token refreshed:", data);

        // Сохраняем новый access_token
        //localStorage.setItem("access_token", data.access_token);

        //document.getElementById("response").textContent = "Token refreshed successfully!";

        const data = await response.json();
        localStorage.setItem("access_token", data.access_token);
        document.getElementById("response").textContent = JSON.stringify(
            data,
            null,
            2
        );
    } catch (error) {
        console.error("Error during token refresh:", error);
        document.getElementById("response").textContent = `Error: ${error.message}`;
    }
}


/*async function authenticateWithProvider2(provider, endpoint) {
    try {
        // Make a POST request to the server's signup or signin endpoint
        const response = await fetch(endpoint, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                provider: provider,
                redirect_uri: redirectURI,
            }),
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(errorText);
        }

        const data = await response.json();
        accessToken = data.token; // Store the JWT token from the response
        document.getElementById("response").textContent = JSON.stringify(data, null, 2);
        alert(`Authentication successful for ${provider}!`);
    } catch (error) {
        document.getElementById("response").textContent = `Error: ${error.message}`;
    }
}

// Get User Profile
async function getUserProfile2() {
    try {
        const response = await fetch(`${serverBaseURL}/user/profile`, {
            method: "GET",
            headers: { Authorization: `Bearer ${accessToken}` },
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(errorText);
        }

        const data = await response.json();
        document.getElementById("response").textContent = JSON.stringify(data, null, 2);
    } catch (error) {
        document.getElementById("response").textContent = `Error: ${error.message}`;
    }
}*/

/*
// Get User Profile
async function getUserProfile() {
    try {
        const response = await fetch(`${serverBaseURL}/user/profile`, {
            method: "GET",
            headers: { Authorization: `Bearer ${accessToken}` },
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(errorText);
        }

        const data = await response.json();
        document.getElementById("response").textContent = JSON.stringify(data, null, 2);
    } catch (error) {
        document.getElementById("response").textContent = `Error: ${error.message}`;
    }
}
*/

/*
// Auto-handle callback if on the callback page
if (window.location.pathname === "/callback") {
    handleCallback();
}

// Callback handler for the redirect flow
async function handleCallback() {
    const urlParams = new URLSearchParams(window.location.search);
    const code = urlParams.get("code");
    const provider = urlParams.get("state");

    if (!code || !provider) {
        document.getElementById("response").textContent = "Authorization code or provider not found.";
        return;
    }

    try {
        const response = await fetch(`${serverBaseURL}/auth/callback`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                code: code,
                redirect_uri: redirectURI,
                provider: provider,
            }),
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(errorText);
        }

        const data = await response.json();
        accessToken = data.token;
        document.getElementById("response").textContent = JSON.stringify(data, null, 2);
        alert("Callback successful!");
    } catch (error) {
        document.getElementById("response").textContent = `Error: ${error.message}`;
    }
}*/
