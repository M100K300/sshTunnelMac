# SSH Tunnel Utility

This is a simple SSH Tunnel utility written in Python. It allows you to create secure SSH tunnels easily.

## Description

The SSH Tunnel Utility helps you to forward ports securely using SSH. This can be useful for accessing services behind a firewall or for encrypting traffic.

## Features

- Easy to use
- Secure port forwarding
- Lightweight and fast

## Installation Instructions (Mac)

### Prerequisites

- Python 3.x
- `pip` (Python package installer)
- SSH client

#### Steps for prerequisites

1. **Install Python**

    If you don't have Python installed, you can install it using Homebrew. First, install Homebrew if you haven't already:

    ```sh
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    ```

    Then, install Python:

    ```sh
    brew install python
    ```

2. **Install `sshpass`**

    `sshpass` is a utility for non-interactive SSH password authentication. You can install it using Homebrew:

    ```sh
    brew install hudochenkov/sshpass/sshpass
    ```

3. **Install `pip`**

    `pip` is the Python package installer. It should come with Python, but if it's not installed, you can install it using:

    ```sh
    python3 -m ensurepip --upgrade
    ```

4. **Install SSH Client**

    macOS comes with an SSH client pre-installed. You can verify it by running:

    ```sh
    ssh -V
    ```

    If it's not installed, you can install it using Homebrew:

    ```sh
    brew install openssh
    ```

### Steps for app installation

1. **Clone the Repository**

    Open your terminal and run the following command to clone the repository:

    ```sh
    git clone https://github.com/yourusername/ssh_tunnel_util.git
    ```

2. **Navigate to the Project Directory**

    ```sh
    cd ssh_tunnel_util
    ```

3. **Create a Virtual Environment**

    It's a good practice to use a virtual environment to manage dependencies. Run the following commands:

    ```sh
    python3 -m venv venv
    source venv/bin/activate
    ```

4. **Install Dependencies**

    Use `pip` to install the required dependencies:

    ```sh
    pip install -r requirements.txt
    ```

5. **Run the Application**

    You can now run the SSH Tunnel Utility:

    ```sh
    python ssh_tunnel_util.py
    ```

## Usage

To use the SSH Tunnel Utility, follow the instructions provided in the application. Typically, you will need to specify the local port, remote port, and the SSH server details.

## License

This project is licensed under the MIT License.

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request.

## Contact

For any questions or issues, please open an issue on GitHub.
