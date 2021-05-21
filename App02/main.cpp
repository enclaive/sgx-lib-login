#include <stdio.h>
#include <iostream>
#include <string>
#include <tchar.h>
#include <stdlib.h>
#include <fcntl.h>
#include "sgx_urts.h"
#include "enclave_u.h"
#define ENCLAVE_FILE _T("enclave.signed.dll")
#define MAX_BUF_LEN 100
#define MAX_STRING 255
#define MAX_USER 255

void console_output(char* v) {
	printf("%s\n", v);
}

bool validate_credential_constraints(std::string& u_name, std::string& u_pw)  {
	std::cout << "\n\nValidating credentials..." << std::endl;
	if (u_name.size() < 5 || u_pw.size() < 5) {
		std::cout << "Your username has to be at least 5 characters long.\n"
			<< "Your password has to be at least 5 characters long\n"
			<< std::endl;
		return false;
	}
	return true;
}

int main()
{
	_set_fmode(_O_BINARY);

	sgx_enclave_id_t eid;
	sgx_status_t ret = SGX_SUCCESS;
	sgx_launch_token_t token = { 0 };
	int updated = 0;

	// Create the enclave with above launch token.
	ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);
	if (ret != SGX_SUCCESS) {
		printf("App: error %#x, failed to create enclave.\n", ret);
		return -1;
	}

	// Menu entries
	enum menu_entry {
		CREATE_USER,
		VALIDATE_LOGIN,
		PRINT_ALL_CREDENTIALS,
		REMOVE_ALL_CREDENTIALS
	};

	// Print menu
	int m_input = 0;
	std::cout << "---- Main menu ----\n"
		<< menu_entry::CREATE_USER << " : Create new user\n"
		<< menu_entry::VALIDATE_LOGIN << " : Validate user login\n"
		<< menu_entry::PRINT_ALL_CREDENTIALS << " : Print all users\n"
		<< menu_entry::REMOVE_ALL_CREDENTIALS << " : Remove all user credentials\n"
		<< std::endl
		<< "Entry: ";

	std::cin >> m_input;

	// Create an instance of the struct user
	struct user u_credentials;
	std::string u_name;
	std::string u_pw;

	// Validate input
	switch (m_input) {
	case menu_entry::CREATE_USER:
	{
		std::cout << "\n\nYou have chosen to create a new user" << std::endl;

		// Print credentials input
		std::cout << "\nUsername: ";
		std::cin >> u_name;
		std::cout << "\nPassword: ";
		std::cin >> u_pw;

		// Validate the user credential constraints
		if (!validate_credential_constraints(u_name, u_pw)) {
			std::cout << "Bye" << std::endl;
			return 0;
		}

		// Fill the user struct
		u_credentials.username = const_cast<char*>(u_name.c_str());
		u_credentials.password = const_cast<char*>(u_pw.c_str());

		// Create user
		int add_user_ret = 0;
		ecall_add_user(eid, &add_user_ret, &u_credentials);

		// Validate the response of the enclave function
		switch (add_user_ret) {
		case 0:
			std::cout << "User created successfully\n";
			break;
		case 1:
			std::cout << "User already exists\n";
			break;
		default:
			std::cout << "An error occured while adding the user\n";
			break;
		}
		break;
	}
	case menu_entry::VALIDATE_LOGIN:
	{
		std::cout << "\n\nYou have chosen to validate a users credentials" << std::endl;
		// Print credentials input
		std::cout << "\nUsername: ";
		std::cin >> u_name;
		std::cout << "\nPassword: ";
		std::cin >> u_pw;

		// Validate user credential constraints
		if (!validate_credential_constraints(u_name, u_pw)) {
			std::cout << "Bye" << std::endl;
			return 0;
		}

		// Fill the user struct
		u_credentials.username = const_cast<char*>(u_name.c_str());
		u_credentials.password = const_cast<char*>(u_pw.c_str());

		// Call the enclave
		int val_user_ret = 0;
		int sgx_ret = ecall_validate_login(eid, &val_user_ret, &u_credentials);
		// Validate the enclaves return value
		if (sgx_ret == SGX_SUCCESS) {
			switch (val_user_ret) {
			case -1:
				std::cout << "Couldn't open the encrypted file" << std::endl;
				break;
			case 0:
				std::cout << "The users " << u_name << " credentials are incorrect, \n"
					<< "or the user doesn't exists." << std::endl;
				break;
			case 1:
				std::cout << "Welcome back " << u_name << std::endl;
				break;
			default:
				std::cout << "An unkown error occured" << std::endl;
				break;
			}
		}
		else {
			std::cout << "An error occurred while running the enclave. Error code: " 
				<< sgx_ret << std::endl;
		}
		break;
	}
	case menu_entry::PRINT_ALL_CREDENTIALS:
		std::cout << "\n\nYou have chosen to print all user credentials" << std::endl;
		ecall_print_all_user(eid);
		break;
	case menu_entry::REMOVE_ALL_CREDENTIALS:
		std::cout << "\n\nYou have chosen to remove all user credentials" << std::endl;
		ecall_remove_all_credentials(eid);
		break;
	default:
		std::cout << "\n\nYour input is not valid. Bye" << std::endl;
		break;
	}

	if (SGX_SUCCESS != sgx_destroy_enclave(eid))
		return -1;
	return 0;
}