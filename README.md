# Secure File Vault - Code Overview

This document provides an overview of the Secure File Vault application, explaining its structure, functionality, and how to modify different components.

## Application Overview

The Secure File Vault is a PyQt6-based desktop application that provides secure file storage with encryption, user authentication, and malware scanning capabilities. The application allows users to:

1. Register and login with username/password
2. Optionally use Two-Factor Authentication (TOTP)
3. Add files to an encrypted vault
4. Extract files from the vault
5. Delete files from the vault
6. Scan files for malware using ClamAV

## Code Structure

The application is organized into several modules within a single file (`main.py`):

### 1. Utility Functions

- **Database Management**: `init_database()` (lines 64-93)
- **Configuration Management**: `load_config()`, `save_config()` (lines 96-112)
- **Session Management**: `save_session()`, `load_session()`, `clear_session()` (lines 115-139)
- **Encryption Utilities**: `derive_key()`, `encrypt_file()`, `decrypt_file()`, `secure_delete_file()` (lines 142-182)
- **Malware Scanning**: `scan_with_clamscan()`, `move_to_quarantine()` (lines 185-215)

### 2. Core Classes

- **AuthManager** (lines 218-340): Handles user authentication, registration, login, and session management
- **FileManager** (lines 342-403): Manages file operations including adding, retrieving, and deleting files

### 3. UI Components

- **LoginWidget** (lines 406-483): UI for user login and registration
- **VaultWidget** (lines 485-600): UI for the file vault, including file listing and operations
  - **DropFileListWidget** (lines 575-600): Nested class for drag-and-drop file functionality
- **MainWindow** (lines 602-625): Main application window that contains the stacked widget with LoginWidget and VaultWidget

### 4. Application Initialization

- **main()** (lines 627-633): Initializes the database, creates the main window, and starts the application

## Modifying the UI

If you want to modify the UI, you'll need to work with the following classes:

1. **LoginWidget** (lines 406-483): For changes to the login/registration screen
2. **VaultWidget** (lines 485-600): For changes to the main vault screen
3. **MainWindow** (lines 602-625): For changes to the overall application window

Each UI class has an `init_ui()` method that sets up the layout and widgets. You can modify these methods to change the appearance and behavior of the UI.

### Example: Adding a New Button to VaultWidget

To add a new button to the VaultWidget, you would modify the `init_ui()` method of the VaultWidget class:

```python
def init_ui(self):
    # ... existing code ...

    button_layout = QHBoxLayout()
    button_layout.setSpacing(20)

    # ... existing buttons ...

    # Add a new button
    self.new_button = QPushButton("New Button")
    self.new_button.clicked.connect(self.new_button_action)
    self.new_button.setFixedWidth(120)
    button_layout.addWidget(self.new_button)

    # ... rest of the existing code ...

def new_button_action(self):
    # Define what happens when the new button is clicked
    QMessageBox.information(self, "New Button", "New button was clicked!")
```

## ClamAV Integration

The application now has full ClamAV integration with the following features:

1. **Malware Scanning**: Files are automatically scanned for malware when added to the vault using the `scan_with_clamscan()` function (lines 186-223)
2. **Configurable ClamAV Path**: The path to the ClamAV executable can be configured through the settings
3. **ClamAV Configuration Dialog**: A user-friendly dialog for configuring and testing ClamAV
4. **Robust Error Handling**: The application handles cases where ClamAV is not available or returns unexpected results
### ClamAV Configuration

The ClamAV integration includes:

1. **Default Configuration**: The application comes with a default ClamAV path configured to use the included ClamAV installation
2. **Configuration Dialog**: Users can access the ClamAV configuration dialog by clicking the "ClamAV Settings" button in the vault interface
3. **Path Configuration**: Users can set the path to the ClamAV executable through the dialog
4. **Testing Functionality**: Users can test if ClamAV is working correctly through the dialog

### How ClamAV Integration Works

1. When a file is added to the vault, it is first scanned for malware using ClamAV
2. If malware is detected, the file is moved to the quarantine directory
3. If ClamAV is not available or returns an unexpected result, a warning is shown to the user
4. Users can configure the ClamAV path through the settings dialog

### Extending ClamAV Integration

If you want to further enhance the ClamAV integration, you might consider:

1. **Scheduled Scans**: Implement periodic scanning of all files in the vault
2. **Custom Scan Options**: Allow users to configure additional ClamAV scan options
3. **Quarantine Management**: Add functionality to manage quarantined files
4. **Database Updates**: Add functionality to update the ClamAV virus database

## Conclusion

This overview should help you understand the structure of the Secure File Vault application and how to modify it to suit your needs. The application is well-organized with clear separation of concerns between authentication, file management, and UI components.


## 📦 Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/secure-file-management.git
   cd secure-file-management
