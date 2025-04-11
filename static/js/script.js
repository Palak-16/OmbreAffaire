document.addEventListener("DOMContentLoaded", function() {



    const forgotPasswordForm = document.getElementById("forgot-password-form");
    const forgotPasswordMessage = document.getElementById("forgot-password-message");
     
    if (forgotPasswordForm) {
        console.log("Form detected!");  // Debugging
        
        forgotPasswordForm.addEventListener("submit", function (event) {
            event.preventDefault(); // Prevent the default GET request
            console.log("Forgot Password button clicked!");  // Debugging
            const email = document.getElementById("forgot-email").value.trim();
            const csrfToken = document.querySelector("[name=csrfmiddlewaretoken]").value;

            console.log("Submitting forgot password request for:", email);  // Debugging

            fetch("/accounts/send-reset-link/", {
                method: "POST",
                headers: {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "X-CSRFToken": csrfToken,  // Ensure CSRF Token is sent
                },
                body: `email=${encodeURIComponent(email)}`
            })
            .then(response => response.json())
            .then(data => {
                console.log("Response received:", data);  // Debugging
                if (data.message) {
                    forgotPasswordMessage.innerHTML = `<span style="color: green;">${data.message}</span>`;
                } else {
                    forgotPasswordMessage.innerHTML = `<span style="color: red;">${data.error}</span>`;
                }
            })
            .catch(error => console.error("Error:", error));
        });
    }else {
        console.log("Form not found in DOM!");}
        
    // Initialize cart count
    let cartCount = 0;
    const cartCountElement = document.querySelector('.cart-count');

    // Add to cart functionality
    document.querySelectorAll('.product-card .btn').forEach(button => {
        button.addEventListener('click', function() {
            cartCount++;
            cartCountElement.textContent = cartCount;
            showNotification('Item added to cart');
        });
    });

    // Newsletter form submission
    const newsletterForm = document.querySelector('.newsletter-form');
    if (newsletterForm) {
        newsletterForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const email = this.querySelector('input[type="email"]').value;
            if (validateEmail(email)) {
                showNotification('Thank you for subscribing!');
                this.reset();
            } else {
                showNotification('Please enter a valid email address', 'error');
            }
        });
    }

    // Smooth scroll for navigation links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function(e) {
            e.preventDefault();
            document.querySelector(this.getAttribute('href')).scrollIntoView({
                behavior: 'smooth'
            });
        });
    });

    // --------------------------
    // Email OTP Signup Flow
    // --------------------------

    const sendOtpBtn = document.getElementById("send-otp");
    const verifyOtpBtn = document.getElementById("verify-otp");
    const emailInput = document.getElementById("email");
    const otpContainer = document.getElementById("otp-container");
    const otpInput = document.getElementById("otp");
    const newUserFields = document.getElementById("new-user-fields");
    const signupBtn = document.getElementById("signup-btn");

    // Function to display notifications
    function showNotification(message, type = "success") {
        const notification = document.createElement("div");
        notification.className = `notification ${type}`;
        notification.textContent = message;
        document.body.appendChild(notification);
        setTimeout(() => notification.remove(), 3000);
    }

    // Function to validate email format
    function validateEmail(email) {
        const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return re.test(email);
    }
    // Password Strength Validation
function validatePassword(password) {
    const minLength = 8;
    const hasUpperCase = /[A-Z]/.test(password);
    const hasLowerCase = /[a-z]/.test(password);
    const hasNumber = /[0-9]/.test(password);
    const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);

    if (password.length < minLength) {
        return "Password must be at least 8 characters long.";
    }
    if (!hasUpperCase) {
        return "Password must have at least one uppercase letter.";
    }
    if (!hasLowerCase) {
        return "Password must have at least one lowercase letter.";
    }
    if (!hasNumber) {
        return "Password must have at least one number.";
    }
    if (!hasSpecialChar) {
        return "Password must have at least one special character.";
    }
    return "";  // No errors
}

    // Step 1: Send OTP to Email
    sendOtpBtn.addEventListener("click", function() {
        let email = emailInput.value.trim();
        
        if (!validateEmail(email)) {
            showNotification("Please enter a valid email address!", "error");
            return;
        }

        fetch("/accounts/send-otp/", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email })
        })
        .then(response => response.json())
        .then(data => {
            if (data.message === "OTP sent successfully!") {
                otpContainer.classList.remove("d-none"); // Reveal OTP input
                showNotification("OTP sent to " + email);
            } else {
                showNotification(data.error, "error");
            }
        })
        .catch(error => console.error("Error:", error));
    });

    // Step 2: Verify OTP from Email
    verifyOtpBtn.addEventListener("click", function() {
        const otpCode = otpInput.value.trim();
        let email = emailInput.value.trim();

        if (otpCode.length !== 6) {
            showNotification("Please enter a valid 6-digit OTP.", "error");
            return;
        }

        fetch("/accounts/verify-email/", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email, otp: otpCode })
        })
        .then(response => response.json())
        .then(data => {
            if (data.message === "Email verified successfully!") {
                newUserFields.classList.remove("d-none"); // Reveal full signup fields
                showNotification("Email verified! Please complete your signup.");
            } else {
                showNotification("Invalid OTP. Try again!", "error");
            }
        })
        .catch(error => console.error("Error:", error));
    });

    const passwordInput = document.getElementById("password");
const passwordStrengthMsg = document.getElementById("password-strength-msg");

passwordInput.addEventListener("input", function() {
    const passwordError = validatePassword(passwordInput.value);
    passwordStrengthMsg.textContent = passwordError;
    passwordStrengthMsg.style.color = passwordError ? "red" : "green";
});


    // Step 3: Complete Signup for New Users
    signupBtn.addEventListener("click", function(event) {
        event.preventDefault();

        const name = document.getElementById("name").value.trim();
        const password = document.getElementById("password").value.trim();
        let email = emailInput.value.trim();

        if (!name || !password) {
            showNotification("Please fill in all details.", "error");
            return;
        }
         // Validate password
    const passwordError = validatePassword(password);
    if (passwordError) {
        showNotification(passwordError, "error");
        return;
    }

        fetch("/accounts/register/", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ name, email, password })
        })
        .then(response => response.json())
        .then(data => {
            if (data.status === "success") {
                showNotification("Signup Successful! Redirecting...");
                window.location.href = "/"; // Redirect to login page
            } else {
                showNotification("Signup Failed. Try again!", "error");
            }
        })
        .catch(error => console.error("Error:", error));
        
    });

    const loginBtn = document.getElementById("login-btn");
const loginEmailInput = document.getElementById("login-email");
const loginPasswordInput = document.getElementById("login-password");

loginBtn.addEventListener("click", function() {
    const email = loginEmailInput.value.trim();
    const password = loginPasswordInput.value.trim();

    if (!email || !password) {
        showNotification("Please enter both email and password.", "error");
        return;
    }

    fetch("/accounts/login/", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password })
    })
    .then(response => response.json())
    .then(data => {
        if (data.message === "Login successful!") {
            showNotification("Login Successful! Redirecting...");
            setTimeout(() => {
                window.location.href = "/";  // ✅ Redirect to home page
            }, 1500);
        } else {
            showNotification("Invalid email or password.", "error");
        }
    })
    .catch(error => console.error("Error:", error));
});

console.log("✅ script.js is running!");

// Wait for the DOM to fully load
setTimeout(function () {
    const params = new URLSearchParams(window.location.search);
    console.log("URL Params:", params.toString());

    if (params.get("showLogin") === "true") {
        console.log("✅ showLogin detected! Forcing modal open...");

        // ✅ Using Bootstrap’s jQuery method to open modal
        $("#authModal").modal("show");

        // ✅ Remove the parameter from the URL after opening modal
        window.history.replaceState({}, document.title, window.location.pathname);
    } else {
        console.log("❌ showLogin not found in URL.");
    }
}, 1000);  // ✅ Delay added to ensure the page loads


});
