document.addEventListener('DOMContentLoaded', function () {
    const registrationForm = document.querySelector('#registrationForm');
    registrationForm.addEventListener('submit', function (event) {
        const password = document.querySelector('#password').value;
        const regex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{8,}$/;
        if (!regex.test(password)) {
            event.preventDefault();
            event.stopPropagation();
            alert('Le mot de passe doit comporter au moins 8 caractères, dont une majuscule, une minuscule et un chiffre.');
        }
        if (!event.target.checkValidity()) {
            event.preventDefault();
            event.stopPropagation();
            event.target.classList.add('was-validated');
        }
    });

    if (document.querySelector('#success-message')) {
        let countdown = 3;
        const interval = setInterval(() => {
            if (countdown === 0) {
                document.querySelector('#success-message').innerText = "C'est parti!";
                clearInterval(interval);
                setTimeout(() => {
                    window.location.href = 'index.php';
                }, 1000);
            } else {
                document.querySelector('#countdown').innerText = countdown;
                countdown--;
            }
        }, 1000);
    }
});