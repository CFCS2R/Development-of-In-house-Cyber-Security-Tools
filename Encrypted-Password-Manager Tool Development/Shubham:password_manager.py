from tkinter import Tk, Label, Button, Entry
from tkinter import ttk

class root_window:

    def __init__(self, root):
        self.root = root
        self.root.title("Password Manager")
        self.root.geometry("900x500+40+40")

        head_title = Label(self.root, text="Password Manager", width=40, bg="purple", font=("Ariel", 20), padx=10, pady=10, anchor="center").grid(columnspan=4, padx=100, pady=00)

        self.crud_frame = ttk.Frame(self.root)
        self.crud_frame.grid()
        self.create_entry_labels()
        self.create_entry_boxes()
        self.create_crud_buttons()

    def create_entry_labels(self):
        self.col_no = self.row_no = 0
        labels_info = ('ID', 'Website', 'Username', 'Password')
        for label_info in labels_info:
            Label(self.crud_frame, text=label_info, bg='grey', fg="white", font=("Ariel", 15), padx=5, pady=2).grid(row=self.row_no, column=self.col_no, padx=5, pady=10)
            self.col_no+=1

    def create_crud_buttons(self):
        self.row_no+=1
        self.col_no = 0
        buttons_info = (('Save', 'green'), ('Update', 'blue'), ('Delete', 'red'), ('Copy Password', 'yellow'))
        for btn_info in buttons_info:
            Button(self.crud_buttons(), text=btn_info[0], bg=btn_info[1], fg="white", font=("Ariel", 15), padx=5, pady=2).grid(row=self.row_no, column=self.col_no, padx=5, pady=10)
    def create_entry_boxes(self):
        self.row_no+=1
        self.entry_boxes = []
        self.col_no = 0
        for i in range(4):
            show = ""
            if i == 3:
                show = "*"
            entry_box = Entry(self.crud_frame, width=25, background="lightgrey", font=("Ariel", 10), show=show)
            entry_box.grid(row=self.row_no, column=self.col_no, padx=5, pady=10)
            self.col_no+=1
            self.entry_boxes.append(entry_box)

if __name__=="__main__":
    root = Tk()
    root_class= root_window(root)
    root.mainloop()
