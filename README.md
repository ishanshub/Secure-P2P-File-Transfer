
# Secure P2P File Transfer

A peer-to-peer file sharing system that combines concurrency, multithreading, and cryptography written in C.  
On a local network, Other users can browse files you've decided to share, find other peers dynamically, and safely download files across a channel that is authorized and encrypted.

----------

## Key Features

This project is designed to be secure, efficient, and scalable, while demonstrating advanced computer science concepts.

-   **Secure by Design (Pull mechanism):**
    
    -   Users can only _request_ files explicitly shared by peers. This prevents untrusted users from pushing harmful files or flooding the network.
        
-   **End-to-End Encryption:**
    
    -   **Confidentiality:** AES-128-CBC encrypts file contents.
        
    -   **Integrity:** HMAC-SHA256 verifies that files have not been tampered with in transit.
        
    -   **Forward Secrecy:** Each transfer negotiates a unique, temporary session key using Diffie-Hellman, ensuring that past or future transfers remain secure even if a key is compromised.
        
-   **Concurrent and Dynamic Network:**
    
    -   Uses `pthreads` to handle peer discovery, file serving, and user interface simultaneously.
        
    -   Automatically discovers peers on the local network without manual configuration.
        
    -   Maintains a fresh peer list by removing inactive peers.
        
-   **Secure and Modular Codebase:**
    
    -   File sharing is limited to a dedicated `./shared` directory, preventing directory traversal attacks.
        
    -   Modular structure with clear separation of logic across multiple C source and header files, supported by a Makefile for easier maintenance and scalability.
        

----------

## How to Compile and Run

**Prerequisites:**

-   OpenSSL libraries  
    On Debian/Ubuntu:
    `sudo apt-get install libssl-dev` 
    

**Compilation:**
- On Terminal:
	`make` 
	This builds a single executable named `secure_p2p`.

**Running the Application:**
`./secure_p2p` 

-   The program will prompt for your name and a port number (e.g., 8080).
   
-   If the `./shared` directory does not exist, it will be created automatically.
    
-   Place files you want to share inside `./shared`.
    

**Usage:**

-   Once running, your program will automatically discover other peers on the same network who are also running it.
    
-   Use the on-screen menu to list discovered peers and download available files.
    

----------

## Project Story

The project evolved through several iterative phases:

**Phase 1: Concurrent P2P Foundation**

-   Focused on creating a stable, multithreaded framework using `pthreads`.
    
-   Added basic AES encryption early to establish a security baseline.
    
-   Implemented real-time peer discovery.
    

**Phase 2: Channel Security Enhancements**

-   Added Diffie-Hellman key exchange to achieve forward secrecy.
    
-   Added HMAC-SHA256 to protect data integrity.
    
-   Introduced a peer-cleaning thread to maintain an up-to-date peer list.
    

**Phase 3: Safer Protocol Design and Modularization**

-   Recognized risks of a “push” model; redesigned the protocol to a safer “pull” approach.
    
-   Restructured the codebase to be modular and easier to maintain or extend.
    

----------

## Known Issues and Future Improvements

-   **Man-in-the-Middle (MitM) Risk:**
    
    -   Current Diffie-Hellman exchange is anonymous. An attacker on the same network could intercept the initial key exchange.
        
    -   Improvement: add authentication, e.g., sign DH public keys with pre-shared keys or certificates.
        
-   **Key Derivation:**
    
    -   Currently, the AES key is derived by truncating the DH shared secret.
        
    -   Improvement: use a Key Derivation Function (KDF) like HKDF to securely produce separate keys for encryption and HMAC.
        
-   **Connection Handling:**
    
    -   The client disconnects after retrieving the file list and reconnects to download a file.
        
    -   Improvement: keep the TCP connection open to serve multiple requests over the same secure channel, improving efficiency.
