class EnhancedDialog {
    constructor() {
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', () => this.init());
        } else {
            this.init();
        }
    }

    init() {
        // Create dialog HTML
        const dialogHTML = `
            <div id="enhancedDialog" class="dialog-overlay">
                <div class="dialog-content">
                    <div class="dialog-header">
                        <h3 id="dialogTitle">Notification</h3>
                        <button class="dialog-close" onclick="enhancedDialog.hide()">&times;</button>
                    </div>
                    <div class="dialog-body">
                        <p id="dialogMessage"></p>
                    </div>
                    <div class="dialog-footer" id="dialogFooter">
                        <button class="dialog-btn dialog-btn-primary" id="dialogOkBtn">Close</button>
                    </div>
                </div>
            </div>
        `;

        // Add dialog to body
        document.body.insertAdjacentHTML('beforeend', dialogHTML);

        // Initialize properties
        this.dialog = document.getElementById('enhancedDialog');
        this.footer = document.getElementById('dialogFooter');
        this.okButton = document.getElementById('dialogOkBtn');
        this.confirmCallback = null;

        // Add click outside to close
        window.onclick = (event) => {
            if (event.target === this.dialog) {
                this.hide();
            }
        };

        // Add styles
        const styles = `
            .dialog-overlay {
                display: none;
                position: fixed;
                top: 0;
                left: 0;
                right: 0;
                bottom: 0;
                background-color: rgba(0, 0, 0, 0.5);
                z-index: 1000;
                justify-content: center;
                align-items: center;
                backdrop-filter: blur(5px);
            }

            .dialog-content {
                background: white;
                border-radius: 8px;
                width: 90%;
                max-width: 400px;
                box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
                animation: dialogSlideUp 0.3s ease-out;
            }

            @keyframes dialogSlideUp {
                from {
                    transform: translateY(20px);
                    opacity: 0;
                }
                to {
                    transform: translateY(0);
                    opacity: 1;
                }
            }

            .dialog-header {
                padding: 1rem;
                border-bottom: 1px solid #e9ecef;
                display: flex;
                justify-content: space-between;
                align-items: center;
            }

            .dialog-header h3 {
                margin: 0;
                font-size: 1.25rem;
                color: #2c3e50;
            }

            .dialog-close {
                background: none;
                border: none;
                font-size: 1.5rem;
                cursor: pointer;
                color: #6c757d;
            }

            .dialog-body {
                justify-content: center;
                align-items: center;
                padding: 1rem;
                color: #4a5568;
            }
            #dialogMessage {
                text-align: center;
                align-items: center;
            }

            .dialog-footer {
                padding: 1rem;
                border-top: 1px solid #e9ecef;
                display: flex;
                justify-content: center;
                gap: 0.5rem;
            }

            .dialog-footer.confirm-mode {
                justify-content: flex-end;
            }

            .dialog-btn {
                padding: 0.5rem 1rem;
                border-radius: 4px;
                border: none;
                cursor: pointer;
                font-size: 0.875rem;
                transition: all 0.2s;
                min-width: 100px;
            }

            .dialog-btn-primary {
                background: #3b82f6;
                color: white;
            }

            .dialog-btn-primary:hover {
                background: #2563eb;
            }

            .dialog-btn-secondary {
                background: #e5e7eb;
                color: #4b5563;
            }

            .dialog-btn-secondary:hover {
                background: #d1d5db;
            }
        `;

        const styleSheet = document.createElement("style");
        styleSheet.textContent = styles;
        document.head.appendChild(styleSheet);
    }

    // Hiển thị dạng thông báo đơn giản
    showMessage(options = {}) {
        const { title, message } = options;
        this.dialog.style.display = 'flex';
        document.getElementById('dialogTitle').textContent = title || 'Notification';
        document.getElementById('dialogMessage').textContent = message || '';
        
        // Reset về dạng thông báo đơn giản
        this.footer.className = 'dialog-footer';
        this.footer.innerHTML = `
            <button class="dialog-btn dialog-btn-primary" onclick="enhancedDialog.hide()">Close</button>
        `;
    }

    // Hiển thị dạng xác nhận
    showConfirm(options = {}) {
        const { title, message, onConfirm } = options;
        this.dialog.style.display = 'flex';
        document.getElementById('dialogTitle').textContent = title || 'Confirm';
        document.getElementById('dialogMessage').textContent = message || 'Bạn có chắc chắn muốn thực hiện hành động này?';
        this.confirmCallback = onConfirm;

        // Chuyển sang dạng confirm
        this.footer.className = 'dialog-footer confirm-mode';
        this.footer.innerHTML = `
            <button class="dialog-btn dialog-btn-secondary" onclick="enhancedDialog.hide()">Cancel</button>
            <button class="dialog-btn dialog-btn-primary" id="dialogConfirmBtn">Confirm</button>
        `;

        // Thêm sự kiện cho nút confirm
        document.getElementById('dialogConfirmBtn').onclick = () => {
            if (this.confirmCallback) {
                this.confirmCallback();
            }
            this.hide();
        };
    }

    hide() {
        this.dialog.style.display = 'none';
        this.confirmCallback = null;
    }
}

const enhancedDialog = new EnhancedDialog();
// export default enhancedDialog;
// Create global instance
window.enhancedDialog = enhancedDialog;
