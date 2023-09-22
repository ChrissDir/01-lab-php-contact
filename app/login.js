document.addEventListener("DOMContentLoaded", function() {
    let lockout = JSON.parse(document.getElementById('lockout-data').dataset.lockout);
    let remainingTime = JSON.parse(document.getElementById('lockout-data').dataset.remainingTime);
    
    if (lockout) {
        let submitButton = document.querySelector("button[type='submit']");
        submitButton.disabled = true;
        let countdown = setInterval(function() {
            remainingTime--;
            if (remainingTime <= 0) {
                clearInterval(countdown);
                submitButton.disabled = false;
            } else {
                submitButton.innerText = `Se connecter (Attendez ${remainingTime}s)`;
            }
        }, 1000);
    }
});