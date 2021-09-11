import json
import hashlib
from virus_total_apis import PublicApi
from tkinter import *
from tkinter import ttk
from tkinter import filedialog
import time
import os
from tkinter import messagebox
from virustotal_python import Virustotal


class Threat_Scanner:
    def __init__(self):
        # Virus Total API
        self.indicator = False
        self.virus_total = PublicApi("5b34fd9e6afc7c01df9f9f9092a5b2d690ae3ae0d676e04ad4ab5df910567e49")

        self.root = Tk()
        self.root.title("Amrash Threat Scanner 2021")
        self.root.geometry("1000x700")
        self.root.resizable(0, 0)
        self.root.config(bg="#70adda")
        self.root.iconbitmap("icon.ico")

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack()
        self.frame1 = Frame(self.notebook, width=1000, height=700, bg="#70adda")
        self.frame2 = Frame(self.notebook, width=1000, height=700, bg="#70adda")

        self.frame1.pack(fill=BOTH, expand=1)
        self.frame2.pack(fill=BOTH, expand=1)

        self.notebook.add(self.frame1,
        text="                                                                      URL SCANNER               "
             "                                                         ")
        self.notebook.add(self.frame2,
        text="                                                                      FILE SCANNER              "
             "                                                         ")
        # URL SCANNER
        self.label = Label(self.frame1, text="ENTER AN URL TO SCAN:", bg="#70adda", font=("algerian", 14))
        self.label.place(x=10, y=20)

        self.entry = Entry(self.frame1, font=("times", 14))
        self.entry.place(x=10, y=65, width=975, height=30)

        self.button = Button(self.frame1, text="Scan", font="times 12", bg="#ffffff", width=10, height=1,
                             command=self.url_scanner)
        self.button.place(x=450, y=120)
        self.entry.focus()

        self.label = Label(self.frame1, text="Progress:", bg="#70adda", font=("times", 14))
        self.label.place(x=10, y=180)

        self.Progress = ttk.Progressbar(self.frame1, orient=HORIZONTAL, length=100, mode='determinate')
        self.Progress.place(x=10, y=220, width=980, height=30)

        # File Scanner
        self.label1 = Label(self.frame2, text="BROWSE A File TO SCAN:", bg="#70adda", font=("algerian", 14))
        self.label1.place(x=10, y=20)

        self.var = StringVar()
        self.entry1 = Entry(self.frame2, font=("times", 14),textvariable = self.var)
        self.entry1.place(x=10, y=65, width=800, height=30)
        self.browse = Button(self.frame2, text="Browse", font="times 12", bg="#ffffff", width=10, height=1,
                             command=self.file_open)

        self.browse.place(x=850,y=65)

        self.button1 = Button(self.frame2, text="Scan", font="times 12", bg="#ffffff", width=10, height=1,
                             command=self.FileScanner)
        self.button1.place(x=380, y=120)
        self.entry1.focus()

        self.label1 = Label(self.frame2, text="Progress:", bg="#70adda", font=("times", 14))
        self.label1.place(x=10, y=180)

        self.Progress1 = ttk.Progressbar(self.frame2, orient=HORIZONTAL, length=100, mode='determinate')
        self.Progress1.place(x=10, y=220, width=980, height=30)

        self.root.mainloop()

    def file_open(self):
        self.fileDialog = filedialog.askopenfilename(initialdir="/", title="Select file")
        self.var.set(self.fileDialog)

    def url_scanner(self):
        URL = self.entry.get()
        self.virus_total.scan_url(URL)
        indicator = 0
        while True:
            if 'Scan finished' in str(self.virus_total.get_url_report(URL)):
                print(self.virus_total.get_url_report(URL))
                REP = self.virus_total.get_url_report(URL)['results']['positives']
                self.Progress["value"] = 100
                break
            else:
                if indicator == 50:
                    messagebox.showerror("Error !","Check your Internet Connection")
                    self.Progress["value"] = 0
                    break
                if self.Progress["value"] == 100:
                    self.Progress["value"] = 0
                self.Progress["value"] += 10
                self.root.update_idletasks()
                time.sleep(0.1)
                print("Scan in Progress !")

        if REP == '0' or REP == 0:
            print('SCANNED %s - VERDICT OK [REP=%s]' % (URL, REP))
        else:
            print('SCANNED %s - VERDICT KO [REP=%s]' % (URL, REP))

    def FileScanner(self):
        self.file_path = self.var.get()
        BLOCKSIZE = 65536  # lets read stuff in 64kb chunks!

        fileToOpen = f'{self.file_path}'
        hasher = hashlib.md5()

        if self.Progress1["value"] == 100:
            self.Progress1["value"] = 0

        with open(fileToOpen, 'rb') as afile:
            buf = afile.read(BLOCKSIZE)
            while len(buf) > 0:
                hasher.update(buf)
                buf = afile.read(BLOCKSIZE)

        md5_calculated = hasher.hexdigest()
        response = self.virus_total.get_file_report(md5_calculated)
        indicator = 0

        while True:
            json_string = str(json.dumps(response, sort_keys=False, indent=4))
            data = json.loads(json_string)
            try:
                response = data['results']['response_code']
            except Exception:
                response = False
                if indicator == 50:
                    messagebox.showerror("Error !", "Check your internet Connection !")
                    self.Progress1["value"] = 0
                    break
                indicator += 1
                if self.Progress1["value"] == 100:
                    self.Progress1["value"] = 0
                self.Progress1["value"] += 10
                self.root.update_idletasks()
                time.sleep(0.1)

            if response == 1 or response == '1':
                print("Scan Completed")
                self.Progress1["value"] = 100
                print(json_string)
                break

            elif response == 0 or response == '0':
                print("Requires to send file via Post Request")
                try:
                    self.file_scan_request()
                except Exception:
                    messagebox.showerror("Error!","Please Check your Internet Connection")
                break

    def file_scan_request(self):
        # Not Completed Yet
        """ """
        try:
            file_path = self.file_path
            virus_total = Virustotal(API_KEY="5b34fd9e6afc7c01df9f9f9092a5b2d690ae3ae0d676e04ad4ab5df910567e49")
            files = {"file": (os.path.basename(file_path), open(os.path.abspath(file_path), "rb"))}
            response = virus_total.request("file/scan", files=files, method="POST")
            result = response.json()
            scan_id = result['sha256']
            resp = virus_total.request("file/report", {"resource": scan_id})
            resp_code = resp.response_code
            if resp_code == "-2":
                messagebox.showinfo("Queued ", "Your resource is queued for analysis. Come back later !")
            print(resp.json())
        except Exception:
            messagebox.showerror("Error !", "API Request Exceeded, Try again later.")
            self.Progress1["value"] = 0

Threat_Scanner()
