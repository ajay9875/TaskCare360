function toggleDarkMode() {
    const body = document.body;
    body.classList.toggle('dark-mode');

    // Store user preference in localStorage
    if (body.classList.contains('dark-mode')) {
        localStorage.setItem('theme', 'dark');
        document.querySelector(".Theme-btn button").innerText = "🌙 Light Mode";
        document.querySelector(".Theme-btn button").style.backgroundColor = "whitesmoke";
        document.querySelector(".Theme-btn button").style.color = "black";

    } else {
        localStorage.setItem('theme', 'light');
        document.querySelector(".Theme-btn button").innerText = "🌙 Dark Mode";
        document.querySelector(".Theme-btn button").style.backgroundColor = "black";
        document.querySelector(".Theme-btn button").style.color = "white";

    }
}

// Load theme preference from localStorage
document.addEventListener("DOMContentLoaded", function () {
    if (localStorage.getItem('theme') === 'dark') {
        document.body.classList.add('dark-mode');
    }
});