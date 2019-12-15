#pragma once

#include <string>

#include "login_key.h"

namespace tarabloader {

	using namespace System;
	using namespace System::ComponentModel;
	using namespace System::Collections;
	using namespace System::Windows::Forms;
	using namespace System::Data;
	using namespace System::Drawing;
	using namespace System::Runtime::InteropServices;	//use for String^ to std::string/char*

	/// <summary>
	/// Zusammenfassung für login
	/// </summary>
	public ref class login : public System::Windows::Forms::Form
	{

	private: System::Windows::Forms::Panel^ panel1;
	private: System::Windows::Forms::Button^ btn_key;
	private: System::Windows::Forms::Button^ btn_submit;


	private: System::Windows::Forms::Panel^ panel2;
	private: System::Windows::Forms::Panel^ panel3;
	private: System::Windows::Forms::TextBox^ textBox2;
	private: System::Windows::Forms::Label^ label2;
	private: System::Windows::Forms::Label^ label3;
	private: System::Windows::Forms::TextBox^ textBox1;


	private: Point offset;
	private: System::Windows::Forms::PictureBox^ pictureBox1;
	private: System::Windows::Forms::Label^ lab_login;
	private: System::Windows::Forms::Label^ label1;
	private: System::Windows::Forms::Panel^ top_col;
	private: bool dragging;

	public:
		login(void)
		{
			InitializeComponent();
			//
			//TODO: Konstruktorcode hier hinzufügen.
			//
		}

	protected:
		/// <summary>
		/// Verwendete Ressourcen bereinigen.
		/// </summary>
		~login()
		{
			if (components)
			{
				delete components;
			}
		}




	protected:

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
			System::ComponentModel::ComponentResourceManager^ resources = (gcnew System::ComponentModel::ComponentResourceManager(login::typeid));
			this->panel1 = (gcnew System::Windows::Forms::Panel());
			this->btn_key = (gcnew System::Windows::Forms::Button());
			this->btn_submit = (gcnew System::Windows::Forms::Button());
			this->panel2 = (gcnew System::Windows::Forms::Panel());
			this->panel3 = (gcnew System::Windows::Forms::Panel());
			this->textBox2 = (gcnew System::Windows::Forms::TextBox());
			this->label2 = (gcnew System::Windows::Forms::Label());
			this->label3 = (gcnew System::Windows::Forms::Label());
			this->textBox1 = (gcnew System::Windows::Forms::TextBox());
			this->pictureBox1 = (gcnew System::Windows::Forms::PictureBox());
			this->lab_login = (gcnew System::Windows::Forms::Label());
			this->label1 = (gcnew System::Windows::Forms::Label());
			this->top_col = (gcnew System::Windows::Forms::Panel());
			(cli::safe_cast<System::ComponentModel::ISupportInitialize^>(this->pictureBox1))->BeginInit();
			this->SuspendLayout();
			// 
			// panel1
			// 
			this->panel1->BackColor = System::Drawing::Color::Coral;
			this->panel1->Location = System::Drawing::Point(41, 62);
			this->panel1->Name = L"panel1";
			this->panel1->Size = System::Drawing::Size(195, 3);
			this->panel1->TabIndex = 8;
			// 
			// btn_key
			// 
			this->btn_key->BackColor = System::Drawing::Color::Coral;
			this->btn_key->FlatStyle = System::Windows::Forms::FlatStyle::Flat;
			this->btn_key->Font = (gcnew System::Drawing::Font(L"Consolas", 9.75F, System::Drawing::FontStyle::Bold, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(0)));
			this->btn_key->ForeColor = System::Drawing::Color::FromArgb(static_cast<System::Int32>(static_cast<System::Byte>(38)), static_cast<System::Int32>(static_cast<System::Byte>(38)),
				static_cast<System::Int32>(static_cast<System::Byte>(38)));
			this->btn_key->Location = System::Drawing::Point(41, 126);
			this->btn_key->Name = L"btn_key";
			this->btn_key->Size = System::Drawing::Size(75, 30);
			this->btn_key->TabIndex = 17;
			this->btn_key->Text = L"Key";
			this->btn_key->UseVisualStyleBackColor = false;
			this->btn_key->Click += gcnew System::EventHandler(this, &login::Btn_quit_Click);
			// 
			// btn_submit
			// 
			this->btn_submit->BackColor = System::Drawing::Color::Coral;
			this->btn_submit->FlatStyle = System::Windows::Forms::FlatStyle::Flat;
			this->btn_submit->Font = (gcnew System::Drawing::Font(L"Consolas", 9.75F, System::Drawing::FontStyle::Bold, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(0)));
			this->btn_submit->ForeColor = System::Drawing::Color::FromArgb(static_cast<System::Int32>(static_cast<System::Byte>(38)), static_cast<System::Int32>(static_cast<System::Byte>(38)),
				static_cast<System::Int32>(static_cast<System::Byte>(38)));
			this->btn_submit->Location = System::Drawing::Point(162, 126);
			this->btn_submit->Name = L"btn_submit";
			this->btn_submit->Size = System::Drawing::Size(75, 30);
			this->btn_submit->TabIndex = 16;
			this->btn_submit->Text = L"Submit";
			this->btn_submit->UseVisualStyleBackColor = false;
			this->btn_submit->Click += gcnew System::EventHandler(this, &login::Btn_login_Click);
			// 
			// panel2
			// 
			this->panel2->BackColor = System::Drawing::Color::WhiteSmoke;
			this->panel2->Location = System::Drawing::Point(41, 89);
			this->panel2->Name = L"panel2";
			this->panel2->Size = System::Drawing::Size(196, 1);
			this->panel2->TabIndex = 15;
			// 
			// panel3
			// 
			this->panel3->BackColor = System::Drawing::Color::WhiteSmoke;
			this->panel3->Location = System::Drawing::Point(41, 119);
			this->panel3->Name = L"panel3";
			this->panel3->Size = System::Drawing::Size(196, 1);
			this->panel3->TabIndex = 13;
			// 
			// textBox2
			// 
			this->textBox2->BackColor = System::Drawing::Color::FromArgb(static_cast<System::Int32>(static_cast<System::Byte>(38)), static_cast<System::Int32>(static_cast<System::Byte>(38)),
				static_cast<System::Int32>(static_cast<System::Byte>(38)));
			this->textBox2->BorderStyle = System::Windows::Forms::BorderStyle::None;
			this->textBox2->Font = (gcnew System::Drawing::Font(L"Consolas", 9.75F, System::Drawing::FontStyle::Regular, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(0)));
			this->textBox2->ForeColor = System::Drawing::SystemColors::Window;
			this->textBox2->Location = System::Drawing::Point(112, 101);
			this->textBox2->Name = L"textBox2";
			this->textBox2->Size = System::Drawing::Size(125, 16);
			this->textBox2->TabIndex = 14;
			this->textBox2->Text = L"usr_pw";
			// 
			// label2
			// 
			this->label2->AutoSize = true;
			this->label2->Font = (gcnew System::Drawing::Font(L"Consolas", 8.25F));
			this->label2->ForeColor = System::Drawing::SystemColors::ControlDark;
			this->label2->Location = System::Drawing::Point(38, 103);
			this->label2->Name = L"label2";
			this->label2->Size = System::Drawing::Size(61, 13);
			this->label2->TabIndex = 12;
			this->label2->Text = L"password:";
			// 
			// label3
			// 
			this->label3->AutoSize = true;
			this->label3->Font = (gcnew System::Drawing::Font(L"Consolas", 8.25F));
			this->label3->ForeColor = System::Drawing::SystemColors::ControlDark;
			this->label3->Location = System::Drawing::Point(38, 73);
			this->label3->Name = L"label3";
			this->label3->Size = System::Drawing::Size(37, 13);
			this->label3->TabIndex = 11;
			this->label3->Text = L"name:";
			// 
			// textBox1
			// 
			this->textBox1->BackColor = System::Drawing::Color::FromArgb(static_cast<System::Int32>(static_cast<System::Byte>(38)), static_cast<System::Int32>(static_cast<System::Byte>(38)),
				static_cast<System::Int32>(static_cast<System::Byte>(38)));
			this->textBox1->BorderStyle = System::Windows::Forms::BorderStyle::None;
			this->textBox1->Font = (gcnew System::Drawing::Font(L"Consolas", 9.75F, System::Drawing::FontStyle::Regular, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(0)));
			this->textBox1->ForeColor = System::Drawing::SystemColors::Window;
			this->textBox1->Location = System::Drawing::Point(112, 71);
			this->textBox1->Name = L"textBox1";
			this->textBox1->Size = System::Drawing::Size(125, 16);
			this->textBox1->TabIndex = 10;
			this->textBox1->Text = L"usr_name";
			// 
			// pictureBox1
			// 
			this->pictureBox1->Image = (cli::safe_cast<System::Drawing::Image^>(resources->GetObject(L"pictureBox1.Image")));
			this->pictureBox1->Location = System::Drawing::Point(0, 6);
			this->pictureBox1->Name = L"pictureBox1";
			this->pictureBox1->Size = System::Drawing::Size(50, 50);
			this->pictureBox1->SizeMode = System::Windows::Forms::PictureBoxSizeMode::StretchImage;
			this->pictureBox1->TabIndex = 35;
			this->pictureBox1->TabStop = false;
			// 
			// lab_login
			// 
			this->lab_login->AutoSize = true;
			this->lab_login->Font = (gcnew System::Drawing::Font(L"Arial", 9, System::Drawing::FontStyle::Regular, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(0)));
			this->lab_login->ForeColor = System::Drawing::Color::Silver;
			this->lab_login->Location = System::Drawing::Point(127, 44);
			this->lab_login->Name = L"lab_login";
			this->lab_login->Size = System::Drawing::Size(38, 15);
			this->lab_login->TabIndex = 34;
			this->lab_login->Text = L"Login";
			// 
			// label1
			// 
			this->label1->AutoSize = true;
			this->label1->Font = (gcnew System::Drawing::Font(L"Arial", 12, System::Drawing::FontStyle::Bold));
			this->label1->ForeColor = System::Drawing::Color::LightGray;
			this->label1->Location = System::Drawing::Point(262, 9);
			this->label1->Name = L"label1";
			this->label1->Size = System::Drawing::Size(18, 19);
			this->label1->TabIndex = 33;
			this->label1->Text = L"x";
			this->label1->Click += gcnew System::EventHandler(this, &login::Label1_Click);
			// 
			// top_col
			// 
			this->top_col->BackColor = System::Drawing::Color::Coral;
			this->top_col->Location = System::Drawing::Point(1, 1);
			this->top_col->Name = L"top_col";
			this->top_col->Size = System::Drawing::Size(299, 5);
			this->top_col->TabIndex = 32;
			// 
			// login
			// 
			this->AutoScaleDimensions = System::Drawing::SizeF(6, 13);
			this->AutoScaleMode = System::Windows::Forms::AutoScaleMode::Font;
			this->BackColor = System::Drawing::Color::FromArgb(static_cast<System::Int32>(static_cast<System::Byte>(38)), static_cast<System::Int32>(static_cast<System::Byte>(38)),
				static_cast<System::Int32>(static_cast<System::Byte>(38)));
			this->ClientSize = System::Drawing::Size(282, 175);
			this->Controls->Add(this->pictureBox1);
			this->Controls->Add(this->lab_login);
			this->Controls->Add(this->label1);
			this->Controls->Add(this->top_col);
			this->Controls->Add(this->btn_key);
			this->Controls->Add(this->btn_submit);
			this->Controls->Add(this->panel2);
			this->Controls->Add(this->panel3);
			this->Controls->Add(this->textBox2);
			this->Controls->Add(this->label2);
			this->Controls->Add(this->label3);
			this->Controls->Add(this->textBox1);
			this->Controls->Add(this->panel1);
			this->FormBorderStyle = System::Windows::Forms::FormBorderStyle::None;
			this->Name = L"login";
			this->Text = L"login";
			this->Load += gcnew System::EventHandler(this, &login::Login_Load);
			this->MouseDown += gcnew System::Windows::Forms::MouseEventHandler(this, &login::Login_MouseDown);
			this->MouseMove += gcnew System::Windows::Forms::MouseEventHandler(this, &login::Login_MouseMove);
			this->MouseUp += gcnew System::Windows::Forms::MouseEventHandler(this, &login::Login_MouseUp);
			(cli::safe_cast<System::ComponentModel::ISupportInitialize^>(this->pictureBox1))->EndInit();
			this->ResumeLayout(false);
			this->PerformLayout();

		}
#pragma endregion
	private: System::Void Login_Load(System::Object^ sender, System::EventArgs^ e) {
		//Make sure it isn't moving when we open the form.
		this->dragging = false;
	}


	private: System::Void PictureBox1_Click(System::Object^ sender, System::EventArgs^ e) {
	}
	private: System::Void Label1_Click_1(System::Object^ sender, System::EventArgs^ e) {
		Close();
	}
	private: System::Void Login_MouseDown(System::Object^ sender, System::Windows::Forms::MouseEventArgs^ e) {
		//tell the form its gonna be draggin'
		this->dragging = true;
		this->offset = Point(e->X, e->Y);
	}
	private: System::Void Login_MouseUp(System::Object^ sender, System::Windows::Forms::MouseEventArgs^ e) {
		this->dragging = false; //this bool is awesome
	}

	private: System::Void Login_MouseMove(System::Object^ sender, System::Windows::Forms::MouseEventArgs^ e) {
		if (this->dragging) { //Move, soldier, MOVE!
			Point currentScreenPos = PointToScreen(e->Location);
			Location = Point(currentScreenPos.X - this->offset.X,
			currentScreenPos.Y - this->offset.Y);
		}
	}

	private: System::Void Btn_login_Click(System::Object^ sender, System::EventArgs^ e) {	//important login shit
		System::String^ str_name = textBox1->Text;
		System::String^ str_passwd = textBox2->Text;

		char* name = (char*)(void*)Marshal::StringToHGlobalAnsi(str_name);
		char* password = (char*)(void*)Marshal::StringToHGlobalAnsi(str_passwd);


	}

	private: System::Void Btn_quit_Click(System::Object^ sender, System::EventArgs^ e) {	//login using license key
		this->Hide();
		login_key^ key_log = gcnew login_key(this);
		key_log->ShowDialog();
	}
private: System::Void Label1_Click(System::Object^ sender, System::EventArgs^ e) {
	exit(NULL);
}
};
}
