class SpinnerService {
    constructor() {
        this.isInitialized = false; 
        // Đợi DOM load xong mới init
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', () => this.init());
        } else {
            this.init();
        }
    }

    init() {
        // Tạo các elements
        const spinnerContainer = document.createElement('div');
        spinnerContainer.className = 'spinner-container';
        
        const spinner = document.createElement('span');
        spinner.className = 'spinner';
        spinner.id = 'submitSpinner';
        
        // Thêm spinner vào container
        spinnerContainer.appendChild(spinner);
        
        // Thêm styles
        const style = document.createElement('style');
        style.textContent = `
            .spinner-container {
                position: fixed;
                top: 0;
                left: 0;
                right: 0;
                bottom: 0;
                display: none;
                justify-content: center;
                align-items: center;
                z-index: 1000;
                background-color: rgba(0, 0, 0, 0.5);
                backdrop-filter: blur(2px);
                opacity: 0;
                transition: opacity 0.3s ease-in-out;
            }

            .spinner-container.show {
                opacity: 1;
            }

            .spinner {
                background: white;
                padding: 20px;
                border-radius: 8px;
                display: inline-block;
                width: 40px;
                height: 40px;
                border: 4px solid #f3f3f3;
                border-top: 4px solid #3498db;
                border-radius: 50%;
                animation: spin 1s linear infinite;
            }

            @keyframes spin {
                0% { transform: rotate(0deg); }
                100% { transform: rotate(360deg); }
            }
        `;
        
        // Thêm elements vào document
        document.head.appendChild(style);
        document.body.appendChild(spinnerContainer);
        
        // Lưu reference đến spinner container
        this.spinnerContainer = spinnerContainer;
        this.isInitialized = true;
        console.log('Check Spinner container initialized.');
    }

    show() {
        if (!this.isInitialized) {
            console.error('Spinner container is not initialized.');
            return;
        }
        console.log('show spinner');
        this.spinnerContainer.style.display = 'flex';
        requestAnimationFrame(() => {
            this.spinnerContainer.classList.add('show');
        });
    }

    hide() {
        if (!this.isInitialized) {
            console.error('Spinner container is not initialized.');
            return;
        }
        console.log('hide spinner');
        this.spinnerContainer.classList.remove('show');
        setTimeout(() => {
            this.spinnerContainer.style.display = 'none';
        }, 300);
    }
}

// Tạo và export instance
window.spinnerService = new SpinnerService();