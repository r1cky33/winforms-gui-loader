#pragma once

#include <string>

#include "loader.h"

namespace tarabloader {

	using namespace System;
	using namespace System::ComponentModel;
	using namespace System::Collections;
	using namespace System::Windows::Forms;
	using namespace System::Data;
	using namespace System::Drawing;
	using namespace System::Runtime::InteropServices;	//use for String^ to std::string/char*

	/// <summary>
	/// Zusammenfassung für login_key
	/// </summary>
	public ref class login_key : public System::Windows::Forms::Form
	{
	private: Point offset;
	private: System::Windows::Forms::Button^ btn_login;

	private: bool dragging;

	public:
		Form^ obj;
		login_key(void)
		{
			InitializeComponent();
			//
			//TODO: Konstruktorcode hier hinzufügen.
			//
		}

		login_key(Form^ obj1) {
			obj = obj1;
			InitializeComponent();
		}

	protected:
		/// <summary>
		/// Verwendete Ressourcen bereinigen.
		/// </summary>
		~login_key()
		{
			if (components)
			{
				delete components;
			}
		}
	private: System::Windows::Forms::PictureBox^ pictureBox1;
	private: System::Windows::Forms::Button^ btn_submit;
	protected:


	private: System::Windows::Forms::Panel^ panel2;

	private: System::Windows::Forms::Label^ label3;
	private: System::Windows::Forms::TextBox^ textBox1;
	private: System::Windows::Forms::Panel^ panel1;
	private: System::Windows::Forms::Label^ lab_login;
	private: System::Windows::Forms::Label^ label1;
	private: System::Windows::Forms::Panel^ top_col;

	private:
		/// <summary>
		/// Erforderliche Designervariable.
		/// </summary>
		System::ComponentModel::Container ^components;

#pragma region Windows Form Designer generated code
		/// <summary>
		/// Erforderliche Methode für die Designerunterstützung.
		/// Der Inhalt der Methode darf nicht mit dem Code-Editor geändert werden.
		/// </summary>
		void InitializeComponent(void)
		{
			System::ComponentModel::ComponentResourceManager^ resources = (gcnew System::ComponentModel::ComponentResourceManager(login_key::typeid));
			this->pictureBox1 = (gcnew System::Windows::Forms::PictureBox());
			this->btn_submit = (gcnew System::Windows::Forms::Button());
			this->panel2 = (gcnew System::Windows::Forms::Panel());
			this->label3 = (gcnew System::Windows::Forms::Label());
			this->textBox1 = (gcnew System::Windows::Forms::TextBox());
			this->panel1 = (gcnew System::Windows::Forms::Panel());
			this->lab_login = (gcnew System::Windows::Forms::Label());
			this->label1 = (gcnew System::Windows::Forms::Label());
			this->top_col = (gcnew System::Windows::Forms::Panel());
			this->btn_login = (gcnew System::Windows::Forms::Button());
			(cli::safe_cast<System::ComponentModel::ISupportInitialize^>(this->pictureBox1))->BeginInit();
			this->SuspendLayout();
			// 
			// pictureBox1
			// 
			this->pictureBox1->Image = (cli::safe_cast<System::Drawing::Image^>(resources->GetObject(L"pictureBox1.Image")));
			this->pictureBox1->Location = System::Drawing::Point(0, 8);
			this->pictureBox1->Name = L"pictureBox1";
			this->pictureBox1->Size = System::Drawing::Size(50, 50);
			this->pictureBox1->SizeMode = System::Windows::Forms::PictureBoxSizeMode::StretchImage;
			this->pictureBox1->TabIndex = 31;
			this->pictureBox1->TabStop = false;
			// 
			// btn_submit
			// 
			this->btn_submit->BackColor = System::Drawing::Color::Coral;
			this->btn_submit->FlatStyle = System::Windows::Forms::FlatStyle::Flat;
			this->btn_submit->Font = (gcnew System::Drawing::Font(L"Consolas", 9.75F, System::Drawing::FontStyle::Bold, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(0)));
			this->btn_submit->ForeColor = System::Drawing::Color::FromArgb(static_cast<System::Int32>(static_cast<System::Byte>(38)), static_cast<System::Int32>(static_cast<System::Byte>(38)),
				static_cast<System::Int32>(static_cast<System::Byte>(38)));
			this->btn_submit->Location = System::Drawing::Point(165, 133);
			this->btn_submit->Name = L"btn_submit";
			this->btn_submit->Size = System::Drawing::Size(75, 30);
			this->btn_submit->TabIndex = 29;
			this->btn_submit->Text = L"Submit";
			this->btn_submit->UseVisualStyleBackColor = false;
			this->btn_submit->Click += gcnew System::EventHandler(this, &login_key::Btn_login_Click);
			// 
			// panel2
			// 
			this->panel2->BackColor = System::Drawing::Color::WhiteSmoke;
			this->panel2->Location = System::Drawing::Point(44, 103);
			this->panel2->Name = L"panel2";
			this->panel2->Size = System::Drawing::Size(196, 1);
			this->panel2->TabIndex = 28;
			this->panel2->Paint += gcnew System::Windows::Forms::PaintEventHandler(this, &login_key::Panel2_Paint);
			// 
			// label3
			// 
			this->label3->AutoSize = true;
			this->label3->Font = (gcnew System::Drawing::Font(L"Consolas", 8.25F));
			this->label3->ForeColor = System::Drawing::SystemColors::ControlDark;
			this->label3->Location = System::Drawing::Point(41, 87);
			this->label3->Name = L"label3";
			this->label3->Size = System::Drawing::Size(31, 13);
			this->label3->TabIndex = 24;
			this->label3->Text = L"key:";
			// 
			// textBox1
			// 
			this->textBox1->BackColor = System::Drawing::Color::FromArgb(static_cast<System::Int32>(static_cast<System::Byte>(38)), static_cast<System::Int32>(static_cast<System::Byte>(38)),
				static_cast<System::Int32>(static_cast<System::Byte>(38)));
			this->textBox1->BorderStyle = System::Windows::Forms::BorderStyle::None;
			this->textBox1->Font = (gcnew System::Drawing::Font(L"Consolas", 9.75F, System::Drawing::FontStyle::Regular, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(0)));
			this->textBox1->ForeColor = System::Drawing::SystemColors::Window;
			this->textBox1->Location = System::Drawing::Point(115, 85);
			this->textBox1->Name = L"textBox1";
			this->textBox1->Size = System::Drawing::Size(125, 16);
			this->textBox1->TabIndex = 23;
			this->textBox1->Text = L"license_key";
			// 
			// panel1
			// 
			this->panel1->BackColor = System::Drawing::Color::Coral;
			this->panel1->Location = System::Drawing::Point(44, 64);
			this->panel1->Name = L"panel1";
			this->panel1->Size = System::Drawing::Size(195, 3);
			this->panel1->TabIndex = 20;
			// 
			// lab_login
			// 
			this->lab_login->AutoSize = true;
			this->lab_login->Font = (gcnew System::Drawing::Font(L"Arial", 9, System::Drawing::FontStyle::Regular, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(0)));
			this->lab_login->ForeColor = System::Drawing::Color::Silver;
			this->lab_login->Location = System::Drawing::Point(127, 46);
			this->lab_login->Name = L"lab_login";
			this->lab_login->Size = System::Drawing::Size(38, 15);
			this->lab_login->TabIndex = 22;
			this->lab_login->Text = L"Login";
			// 
			// label1
			// 
			this->label1->AutoSize = true;
			this->label1->Font = (gcnew System::Drawing::Font(L"Arial", 12, System::Drawing::FontStyle::Bold));
			this->label1->ForeColor = System::Drawing::Color::LightGray;
			this->label1->Location = System::Drawing::Point(262, 11);
			this->label1->Name = L"label1";
			this->label1->Size = System::Drawing::Size(18, 19);
			this->label1->TabIndex = 21;
			this->label1->Text = L"x";
			this->label1->Click += gcnew System::EventHandler(this, &login_key::Label1_Click);
			// 
			// top_col
			// 
			this->top_col->BackColor = System::Drawing::Color::Coral;
			this->top_col->Location = System::Drawing::Point(1, 3);
			this->top_col->Name = L"top_col";
			this->top_col->Size = System::Drawing::Size(299, 5);
			this->top_col->TabIndex = 19;
			// 
			// btn_login
			// 
			this->btn_login->BackColor = System::Drawing::Color::Coral;
			this->btn_login->FlatStyle = System::Windows::Forms::FlatStyle::Flat;
			this->btn_login->Font = (gcnew System::Drawing::Font(L"Consolas", 9.75F, System::Drawing::FontStyle::Bold, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(0)));
			this->btn_login->ForeColor = System::Drawing::Color::FromArgb(static_cast<System::Int32>(static_cast<System::Byte>(38)), static_cast<System::Int32>(static_cast<System::Byte>(38)),
				static_cast<System::Int32>(static_cast<System::Byte>(38)));
			this->btn_login->Location = System::Drawing::Point(44, 133);
			this->btn_login->Name = L"btn_login";
			this->btn_login->Size = System::Drawing::Size(75, 30);
			this->btn_login->TabIndex = 32;
			this->btn_login->Text = L"Login";
			this->btn_login->UseVisualStyleBackColor = false;
			this->btn_login->Click += gcnew System::EventHandler(this, &login_key::Btn_login_Click_1);
			// 
			// login_key
			// 
			this->AutoScaleDimensions = System::Drawing::SizeF(6, 13);
			this->AutoScaleMode = System::Windows::Forms::AutoScaleMode::Font;
			this->BackColor = System::Drawing::Color::FromArgb(static_cast<System::Int32>(static_cast<System::Byte>(38)), static_cast<System::Int32>(static_cast<System::Byte>(38)),
				static_cast<System::Int32>(static_cast<System::Byte>(38)));
			this->ClientSize = System::Drawing::Size(282, 175);
			this->Controls->Add(this->btn_login);
			this->Controls->Add(this->pictureBox1);
			this->Controls->Add(this->btn_submit);
			this->Controls->Add(this->panel2);
			this->Controls->Add(this->label3);
			this->Controls->Add(this->textBox1);
			this->Controls->Add(this->panel1);
			this->Controls->Add(this->lab_login);
			this->Controls->Add(this->label1);
			this->Controls->Add(this->top_col);
			this->FormBorderStyle = System::Windows::Forms::FormBorderStyle::None;
			this->Name = L"login_key";
			this->Text = L"login_key";
			this->Load += gcnew System::EventHandler(this, &login_key::Login_key_Load);
			this->MouseDown += gcnew System::Windows::Forms::MouseEventHandler(this, &login_key::Login_key_MouseDown);
			this->MouseMove += gcnew System::Windows::Forms::MouseEventHandler(this, &login_key::Login_key_MouseMove);
			this->MouseUp += gcnew System::Windows::Forms::MouseEventHandler(this, &login_key::Login_key_MouseUp);
			(cli::safe_cast<System::ComponentModel::ISupportInitialize^>(this->pictureBox1))->EndInit();
			this->ResumeLayout(false);
			this->PerformLayout();

		}
#pragma endregion
	private: System::Void Login_key_Load(System::Object^ sender, System::EventArgs^ e) {
	}


private: System::Void Panel2_Paint(System::Object^ sender, System::Windows::Forms::PaintEventArgs^ e) {
}
private: System::Void Btn_quit_Click(System::Object^ sender, System::EventArgs^ e) {
	this->Hide();
	
}
private: System::Void Login_key_MouseMove(System::Object^ sender, System::Windows::Forms::MouseEventArgs^ e) {
	if (this->dragging) { //Move, soldier, MOVE!
		Point currentScreenPos = PointToScreen(e->Location);
		Location = Point(currentScreenPos.X - this->offset.X,
			currentScreenPos.Y - this->offset.Y);
	}
}
private: System::Void Login_key_MouseDown(System::Object^ sender, System::Windows::Forms::MouseEventArgs^ e) {
	this->dragging = true;
	this->offset = Point(e->X, e->Y);
}
private: System::Void Login_key_MouseUp(System::Object^ sender, System::Windows::Forms::MouseEventArgs^ e) {
	this->dragging = false;
}

private: System::Void Label1_Click(System::Object^ sender, System::EventArgs^ e) {
	Close();
}
private: System::Void Btn_login_Click(System::Object^ sender, System::EventArgs^ e) {
	System::String^ str_key = textBox1->Text;
	char* key = (char*)(void*)Marshal::StringToHGlobalAnsi(str_key);

	System::Threading::Thread::Sleep(500);
	this->Hide();

	load_with_key(key);		// start loader using key
}
private: System::Void Btn_login_Click_1(System::Object^ sender, System::EventArgs^ e) {
	this->Hide();
	obj->Show();
}
};
}
