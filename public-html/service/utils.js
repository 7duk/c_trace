function setValueCookie(name, value, time) {
    let date = new Date();
    date.setTime(date.getTime() + (time * 24 * 60 * 60 * 1000)); 
    let expires = "expires=" + date.toUTCString();
    document.cookie = `${name}=${value};` + expires + "; SameSite=Lax; path=/";
}
function destroyCookie(name) {
    document.cookie = `${name}=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;`;
}

// Gắn vào window để sử dụng toàn cục
window.setValueCookie = setValueCookie;
window.destroyCookie = destroyCookie;
