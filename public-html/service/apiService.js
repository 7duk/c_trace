const axiosInstance = axios.create({
    baseURL: 'https://api.example.com', // URL của API của bạn
    timeout: 30000, // timeout 10 giây
    headers: {
        'Content-Type': 'application/json',
        'ngrok-skip-browser-warning': 'true' 
    },
});

// Token management
const TokenManager = {
    getToken() {
        return localStorage.getItem('access_token');
    },

    setToken(token) {
        localStorage.setItem('access_token', token);
    },

    removeToken() {
        localStorage.removeItem('access_token');
    },

    isTokenExpired(token) {
        if (!token) return true;
        try {
            const payload = JSON.parse(atob(token.split('.')[1]));
            return payload.exp < Date.now() / 1000;
        } catch {
            return true;
        }
    },
    
    refreshTokenPromise: null,

    async refreshToken() {
        // Kiểm tra nếu đã có refresh token request đang diễn ra, nếu có thì trả về promise đó
        if (this.refreshTokenPromise) {
            return this.refreshTokenPromise;
        }

        // Nếu chưa có, tạo một promise mới
        this.refreshTokenPromise = (async () => {
            try {
                const responseConfig = await fetch('./config/config.json');
                const config = await responseConfig.json();
                const userId = localStorage.getItem('user_id');
                const response = await fetch(`${config.url}/api/v1/auth/refresh-token?userId=${userId}`, {
                    method: 'GET',
                    credentials: 'include',
                    headers: {
                        'Content-Type': 'application/json',
                        'ngrok-skip-browser-warning': 'true' 
                    }
                });
                const data = await response.json(); // Đảm bảo parse dữ liệu JSON
                console.log(data.data.accessToken);  
                if (data?.data.accessToken) {
                    this.setToken(data.data.accessToken);
                    setValueCookie('refreshToken', data.data.refreshToken, 30);
                    localStorage.setItem('user_id',data.data.userID);
                    localStorage.setItem('role',data.data.role);
                    localStorage.setItem('mail',data.data.email);
                    return data.data.accessToken;
                }
                return null;
            } catch (error) {
                console.error("message error -->" + error);
                this.removeToken();
                return null;
            } finally {
                // Reset promise sau khi hoàn thành
                this.refreshTokenPromise = null;
            }
        })();

        return this.refreshTokenPromise;
    }
};


// Request interceptor
axiosInstance.interceptors.request.use(
    async config => {
        const token = TokenManager.getToken();
        
        if (token) {
            // Kiểm tra token hết hạn
            if (TokenManager.isTokenExpired(token)) {
                const newToken = await TokenManager.refreshToken();
                if (newToken) {
                    config.headers.Authorization = `Bearer ${newToken}`;
                } else {
                    // Redirect to login if refresh failed
                    window.location.href = './login.htm';
                    return Promise.reject('Session expired');
                }
            } else {
                config.headers.Authorization = `Bearer ${token}`;
            }
        }
        
        return config;
    },
    error => {
        return Promise.reject(error);
    }
);


// Response interceptor
axiosInstance.interceptors.response.use(
    response => {
        return response;
    },
    async error => {
        const originalRequest = error.config;

        // Xử lý các status code
        if (error.response) {
            switch (error.response.status) {
                case 400:
                    enhancedDialog.showMessage({
                        title: "Message",
                        message: error.response.data
                    });
                    break;

                case 401:
                    // Chỉ thử refresh token một lần
                    if (!originalRequest._retry) {
                        originalRequest._retry = true;
                        const newToken = await TokenManager.refreshToken();
                        console.log(newToken);
                        if (newToken) {
                            originalRequest.headers.Authorization = `Bearer ${newToken}`;
                            return axiosInstance(originalRequest); // Thực hiện lại yêu cầu với token mới
                        }
                    }
                    
                    // Nếu refresh token thất bại, chuyển hướng tới trang đăng nhập
                    enhancedDialog.showMessage({
                        title: "Message",
                        message: error.response.data
                    });
                    window.location.href = './login.htm';
                    break;

                case 403:
                    enhancedDialog.showMessage({
                        title: "Message",
                        message: "Don't have permission to perform this function"
                    });
                    break;

                case 404:
                    enhancedDialog.showMessage({
                        title: "Message",
                        message: error.response.data
                    });
                    break;

                case 500:
                    enhancedDialog.showMessage({
                        title: "Message",
                        message: error.response.data
                    });
                    break;

                default:
                    enhancedDialog.showMessage({
                        title: "Message",
                        message: error.response.data
                    });
            }
        } else if (error.request) {
            enhancedDialog.showMessage({
                title: "Message",
                message: 'Could not connect server'
            });
        } else {
            enhancedDialog.showMessage({
                title: "Message",
                message: 'Request failed'
            });
        }

        return Promise.reject(error);
    }
);


// API service sử dụng axios instance
const apiService = {
    async get(url, config = {}) {
        return axiosInstance.get(url, config);
    },

    async post(url, data = {}, config = {}) {
        return axiosInstance.post(url, data, config);
    },

    async put(url, data = {}, config = {}) {
        return axiosInstance.put(url, data, config);
    },

    async delete(url, config = {}) {
        return axiosInstance.delete(url, config);
    }
    
};

window.apiService = apiService;
