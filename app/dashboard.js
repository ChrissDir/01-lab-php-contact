document.addEventListener('DOMContentLoaded', function() {
    let timeoutDuration = 1800000;
    let timeout;

    function logout() {
        window.location.href = 'logout.php';
    }

    function resetTimeout() {
        clearTimeout(timeout);
        timeout = setTimeout(logout, timeoutDuration);
    }

    document.addEventListener('mousemove', resetTimeout);
    document.addEventListener('keypress', resetTimeout);

    resetTimeout();

    document.querySelectorAll('.delete-contact-form').forEach(form => {
        form.addEventListener('submit', function() {
            return confirm("Êtes-vous sûr de vouloir supprimer ce contact?");
        });
    });
});