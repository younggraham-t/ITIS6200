import customtkinter as ctk
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import binascii

#ctkconfig I love CTK
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class AESVisualizerApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("ITIS 3200/6200/8200: The Horrors of IV Reuse")
        self.geometry("1100x850")

        #STATEVARIABLESSSSS
        self.key = os.urandom(32)  # AES-256 (default)
        self.iv = os.urandom(16)   # 128-bit IV (default)
        self.mode = "AES-CTR"      # Default mode

        # Layout
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        #sidebar
        self.sidebar = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        
        self.logo_label = ctk.CTkLabel(self.sidebar, text="AES LAB", font=ctk.CTkFont(size=20, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))

        self.mode_menu = ctk.CTkOptionMenu(self.sidebar, values=["AES-CTR", "AES-CBC"], command=self.change_mode)
        self.mode_menu.grid(row=2, column=0, padx=20, pady=20)

        self.regen_key_btn = ctk.CTkButton(self.sidebar, text="Random Key", fg_color="green", command=self.regenerate_key)
        self.regen_key_btn.grid(row=3, column=0, padx=20, pady=10)

        self.regen_iv_btn = ctk.CTkButton(self.sidebar, text="Random IV", fg_color="#D35B58", hover_color="#C72C41", command=self.regenerate_iv)
        self.regen_iv_btn.grid(row=4, column=0, padx=20, pady=10)

        self.desc_label = ctk.CTkLabel(self.sidebar, text="Instructions:\n\n1. Edit Key/IV manually or generate random.\n2. Observe Ciphertexts.\n3. In CTR, see how XOR leaks data.", 
                                       wraplength=180, justify="left", text_color="gray")
        self.desc_label.grid(row=5, column=0, padx=20, pady=20)

        self.main_frame = ctk.CTkScrollableFrame(self, corner_radius=0)
        self.main_frame.grid(row=0, column=1, sticky="nsew")

        #key and iv pair input
        self.creds_frame = ctk.CTkFrame(self.main_frame)
        self.creds_frame.pack(fill="x", padx=20, pady=10)
        
        self.key_entry = self.create_input_entry(self.creds_frame, "Key (Hex, 64 chars):", binascii.hexlify(self.key).decode())
        self.iv_entry = self.create_input_entry(self.creds_frame, "IV/Nonce (Hex, 32 chars):", binascii.hexlify(self.iv).decode())

        # message inputs
        self.input_frame = ctk.CTkFrame(self.main_frame)
        self.input_frame.pack(fill="x", padx=20, pady=10)

        self.msg_a_entry = self.create_input_entry(self.input_frame, "Message A (M_1):", "Alice pays Bob $100")
        self.msg_b_entry = self.create_input_entry(self.input_frame, "Message B (M_2):", "Alice pays Eve $100")

        #visuarea
        self.vis_frame = ctk.CTkFrame(self.main_frame)
        self.vis_frame.pack(fill="x", padx=20, pady=10)

        self.cipher_a_out = self.create_readonly_entry(self.vis_frame, "Ciphertext A (Hex):")
        self.cipher_b_out = self.create_readonly_entry(self.vis_frame, "Ciphertext B (Hex):")
        
        #attacker view
        self.horror_frame = ctk.CTkFrame(self.main_frame, border_width=2, border_color="#D35B58")
        self.horror_frame.pack(fill="x", padx=20, pady=20)
        
        self.horror_title = ctk.CTkLabel(self.horror_frame, text="THE ATTACKER'S VIEW (XOR Analysis)", font=ctk.CTkFont(size=16, weight="bold"), text_color="#D35B58")
        self.horror_title.pack(pady=10)

        self.xor_cipher_out = self.create_readonly_entry(self.horror_frame, "Cipher A ⊕ Cipher B:")
        self.xor_plain_out = self.create_readonly_entry(self.horror_frame, "Message A ⊕ Message B:")
        self.status_label = ctk.CTkLabel(self.horror_frame, text="STATUS: SAFE", font=ctk.CTkFont(size=14, weight="bold"))
        self.status_label.pack(pady=10)
        self.update_display()

    def create_readonly_entry(self, parent, label_text):
        f = ctk.CTkFrame(parent, fg_color="transparent")
        f.pack(fill="x", pady=5)
        l = ctk.CTkLabel(f, text=label_text, width=180, anchor="w")
        l.pack(side="left")
        e = ctk.CTkEntry(f, font=("Courier", 14))
        e.pack(side="left", fill="x", expand=True)
        e.configure(state="readonly")
        return e

    def create_input_entry(self, parent, label_text, default_text):
        f = ctk.CTkFrame(parent, fg_color="transparent")
        f.pack(fill="x", pady=5)
        l = ctk.CTkLabel(f, text=label_text, width=180, anchor="w")
        l.pack(side="left")
        e = ctk.CTkEntry(f, font=("Courier", 14))
        e.insert(0, default_text)
        e.pack(side="left", fill="x", expand=True)
        e.bind("<KeyRelease>", self.on_text_change)
        return e

    def regenerate_key(self):
        new_key = os.urandom(32)
        self.key_entry.delete(0, "end")
        self.key_entry.insert(0, binascii.hexlify(new_key).decode())
        self.update_display()

    def regenerate_iv(self):
        new_iv = os.urandom(16)
        self.iv_entry.delete(0, "end")
        self.iv_entry.insert(0, binascii.hexlify(new_iv).decode())
        self.update_display()

    def change_mode(self, choice):
        self.mode = choice
        self.update_display()

    def on_text_change(self, event):
        self.update_display()

    def xor_bytes(self, b1, b2):
        res = bytearray()
        # XORing only up to the length of the shorter byte string
        for b1_byte, b2_byte in zip(b1, b2):
            res.append(b1_byte ^ b2_byte)
        return bytes(res)

    def get_valid_hex(self, entry_widget, expected_len_bytes):
        #hex parsing helper
        try:
            hex_str = entry_widget.get().strip().replace(" ", "")
            return binascii.unhexlify(hex_str)
        except:
            # If invalid hex, return random bytes of correct length to prevent crash
            return b'\x00' * expected_len_bytes

    def encrypt(self, msg_bytes, key, iv):
        #encryption helper
        backend = default_backend()
        #truncate/pad key and iv if user input is messy
        if len(key) not in [16, 24, 32]: 
            key = key[:32].ljust(32, b'\0')
        if len(iv) != 16:
            iv = iv[:16].ljust(16, b'\0')

        if self.mode == "AES-CTR":
            cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=backend)
            encryptor = cipher.encryptor()
            return encryptor.update(msg_bytes) + encryptor.finalize()
        else:
            #CBC w/ PKCS7
            pad_len = 16 - (len(msg_bytes) % 16)
            padded_msg = msg_bytes + bytes([pad_len] * pad_len)
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
            encryptor = cipher.encryptor()
            return encryptor.update(padded_msg) + encryptor.finalize()

    def update_field(self, entry, text):
        entry.configure(state="normal")
        entry.delete(0, "end")
        entry.insert(0, text)
        entry.configure(state="readonly")

    def update_display(self):
        #key and iv from input fields
        try:
            raw_key_hex = self.key_entry.get().strip()
            raw_iv_hex = self.iv_entry.get().strip()
            #basic validation
            self.key = binascii.unhexlify(raw_key_hex) if len(raw_key_hex) % 2 == 0 else b'\0'*32
            self.iv = binascii.unhexlify(raw_iv_hex) if len(raw_iv_hex) % 2 == 0 else b'\0'*16
        except:
            pass #keep previous or default

        #get messages
        msg_a = self.msg_a_entry.get().encode('utf-8')
        msg_b = self.msg_b_entry.get().encode('utf-8')

        #encrypt
        try:
            cipher_a = self.encrypt(msg_a, self.key, self.iv)
            cipher_b = self.encrypt(msg_b, self.key, self.iv)
        except Exception as e:
            # Fail silently on UI if inputs are weird
            return

        self.update_field(self.cipher_a_out, binascii.hexlify(cipher_a).decode())
        self.update_field(self.cipher_b_out, binascii.hexlify(cipher_b).decode())

        #xor analysis
        #calculating xor for the overlap length
        min_len = min(len(cipher_a), len(cipher_b))
        
        #cipher xor
        xor_c = self.xor_bytes(cipher_a[:min_len], cipher_b[:min_len])
        
        #plaintext xor (Handling padding for visualization consistency)
        #if cbc, we should conceptually compare padded plaintexts, but for 
        #the tool demo, we want to show the raw message overlap.
        #   however, for the tool to report TRUE, we compare the raw message bytes.
        
        if self.mode == "AES-CBC":
             #in cbc, comparing raw plaintext xor vs cipher xor is meaningless visually
             #so we show a placeholder or the raw xor to prove they don't match.
             xor_p = self.xor_bytes(msg_a[:min_len], msg_b[:min_len])
        else:
             #CTR - cipher xor should exactly match plaintext xor
             xor_p = self.xor_bytes(msg_a[:min_len], msg_b[:min_len])

        self.update_field(self.xor_cipher_out, binascii.hexlify(xor_c).decode())
        self.update_field(self.xor_plain_out, binascii.hexlify(xor_p).decode())

        #status check
        if self.mode == "AES-CTR":
            #check if cipher xor matches plain xor
            #we compare the hex strings of the xor results
            c_hex = binascii.hexlify(xor_c).decode()
            p_hex = binascii.hexlify(xor_p).decode()
            
            if c_hex == p_hex and len(msg_a) > 0:
                self.status_label.configure(text="CRITICAL: KEYSTREAM REUSE DETECTED\nCipher XOR == Plaintext XOR", text_color="#FF4444")
            else:
                self.status_label.configure(text="SAFE (Inputs differ or IV changed)", text_color="green")
        
        elif self.mode == "AES-CBC":
            #check for identical first block
            first_block_a = binascii.hexlify(cipher_a).decode()[:32]
            first_block_b = binascii.hexlify(cipher_b).decode()[:32]
            
            if first_block_a == first_block_b and len(msg_a) > 0:
                self.status_label.configure(text="WARNING: DETERMINISTIC ENCRYPTION\nIdentical blocks detected.", text_color="orange")
            else:
                self.status_label.configure(text="SAFE (Pseudo-random output)", text_color="green")

if __name__ == "__main__":
    app = AESVisualizerApp()
    app.mainloop()