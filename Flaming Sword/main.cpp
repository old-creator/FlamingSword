#include "trusted.hpp"


int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	if (!TrustedMain()){
		MessageBox(NULL,
			L"=====================================\n\n\n\n\n"
			L"[ - ] Something Went Wong!\n"
			L"\n\n\n\n=====================================",

			L"WARNING",
			MB_OK | MB_ICONERROR
		);
		return EXIT_FAILURE;

	}
	return EXIT_SUCCESS;
}
