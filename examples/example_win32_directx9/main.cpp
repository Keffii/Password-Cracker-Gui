#include "imgui.h"
#include "imgui_impl_dx9.h"
#include "imgui_impl_win32.h"
#include <d3d9.h>
#include <tchar.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <vector>
#include <string>
#include <thread>
#include <future>
#include <commdlg.h> // For file dialog
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

// Data
static LPDIRECT3D9              g_pD3D = nullptr;
static LPDIRECT3DDEVICE9        g_pd3dDevice = nullptr;
static bool                     g_DeviceLost = false;
static UINT                     g_ResizeWidth = 0, g_ResizeHeight = 0;
static D3DPRESENT_PARAMETERS    g_d3dpp = {};

// Forward declarations of helper functions
bool CreateDeviceD3D(HWND hWnd);
void CleanupDeviceD3D();
void ResetDevice();
LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

std::string generate_salt() {
    unsigned char salt[16];
    RAND_bytes(salt, sizeof(salt));
    std::ostringstream oss;
    for (int i = 0; i < sizeof(salt); i++) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)salt[i];
    }
    return oss.str();
}

std::string hash_md5(const std::string& input) {
    unsigned char hash[MD5_DIGEST_LENGTH];
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (mdctx == nullptr) {
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }

    if (EVP_DigestInit_ex(mdctx, EVP_md5(), nullptr) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("Failed to initialize digest");
    }

    if (EVP_DigestUpdate(mdctx, input.c_str(), input.size()) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("Failed to update digest");
    }

    if (EVP_DigestFinal_ex(mdctx, hash, nullptr) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("Failed to finalize digest");
    }

    EVP_MD_CTX_free(mdctx);

    std::ostringstream oss;
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        oss << std::hex << std::setw(2) << std::setfill('0') << int(hash[i]);
    }
    return oss.str();
}

std::string hash_sha256(const std::string& input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)input.c_str(), input.size(), hash);
    std::ostringstream oss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return oss.str();
}

void processPasswords(const std::string& input_file, const std::string& md5_output_file, const std::string& sha256_output_file) {
    std::ifstream infile(input_file);
    std::ofstream md5_outfile(md5_output_file);
    std::ofstream sha256_outfile(sha256_output_file);

    md5_outfile << "Password:hash:salt" << std::endl << std::endl;
    sha256_outfile << "Password:hash:salt" << std::endl << std::endl;

    std::string password;
    while (std::getline(infile, password)) {
        std::string salt = generate_salt();
        std::string md5_hash = hash_md5(password + salt);
        std::string sha256_hash = hash_sha256(password + salt);

        md5_outfile << password << ":" << md5_hash << ":" << salt << std::endl;
        sha256_outfile << password << ":" << sha256_hash << ":" << salt << std::endl;
    }
}

std::string openFileDialog() {
    wchar_t filename[MAX_PATH] = L"";
    OPENFILENAMEW ofn;
    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = NULL;
    ofn.lpstrFilter = L"Text Files\0*.txt\0All Files\0*.*\0";
    ofn.lpstrFile = filename;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
    ofn.lpstrDefExt = L"txt";

    if (GetOpenFileNameW(&ofn)) {
        std::wstring ws(filename);
        return std::string(ws.begin(), ws.end());
    }
    return "";
}

std::string findPasswordInFile(const std::string& filePath, const std::string& hash) {
    std::ifstream infile(filePath);
    std::string line;
    while (std::getline(infile, line)) {
        std::istringstream iss(line);
        std::string password, fileHash, salt;
        if (std::getline(iss, password, ':') && std::getline(iss, fileHash, ':') && std::getline(iss, salt)) {
            if (fileHash == hash) {
                return password;
            }
        }
    }
    return "Password not found";
}

std::string readFileContents(const std::string& filePath) {
    std::ifstream infile(filePath);
    std::stringstream buffer;
    buffer << infile.rdbuf();
    return buffer.str();
}

// Main code
//int main(int, char**)

int WinMain(
    HINSTANCE hInstance,
    HINSTANCE hPrevInstance,
    LPSTR lpCmdLine,
    int nCmdShow    

)

{
    // Create application window
    WNDCLASSEXW wc = { sizeof(wc), CS_CLASSDC, WndProc, 0L, 0L, GetModuleHandle(nullptr), nullptr, nullptr, nullptr, nullptr, L"ImGui Example", nullptr };
    ::RegisterClassExW(&wc);
    HWND hwnd = ::CreateWindowW(wc.lpszClassName, L"Password Cracker Gui", WS_OVERLAPPEDWINDOW, 100, 100, 1280, 800, nullptr, nullptr, wc.hInstance, nullptr);

    // Initialize Direct3D
    if (!CreateDeviceD3D(hwnd))
    {
        CleanupDeviceD3D();
        ::UnregisterClassW(wc.lpszClassName, wc.hInstance);
        return 1;
    }

    // Show the window
    ::ShowWindow(hwnd, SW_SHOWDEFAULT);
    ::UpdateWindow(hwnd);

    // Setup Dear ImGui context
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO(); (void)io;
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;     // Enable Keyboard Controls
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableGamepad;      // Enable Gamepad Controls
    io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;         // Enable Docking
    io.ConfigFlags |= ImGuiConfigFlags_ViewportsEnable;       // Enable Multi-Viewport / Platform Windows

    // Setup Dear ImGui style
    ImGui::StyleColorsDark();

    // When viewports are enabled we tweak WindowRounding/WindowBg so platform windows can look identical to regular ones.
    ImGuiStyle& style = ImGui::GetStyle();
    if (io.ConfigFlags & ImGuiConfigFlags_ViewportsEnable)
    {
        style.WindowRounding = 0.0f;
        style.Colors[ImGuiCol_WindowBg].w = 1.0f;
    }

    // Setup Platform/Renderer backends
    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX9_Init(g_pd3dDevice);

    // Our state
    ImVec4 clear_color = ImVec4(0.00f, 0.00f, 0.00f, 1.00f);

    // Main loop
    bool done = false;
    while (!done)
    {
        // Poll and handle messages (inputs, window resize, etc.)
        MSG msg;
        while (::PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE))
        {
            ::TranslateMessage(&msg);
            ::DispatchMessage(&msg);
            if (msg.message == WM_QUIT)
                done = true;
        }
        if (done)
            break;

        // Handle lost D3D9 device
        if (g_DeviceLost)
        {
            HRESULT hr = g_pd3dDevice->TestCooperativeLevel();
            if (hr == D3DERR_DEVICELOST)
            {
                ::Sleep(10);
                continue;
            }
            if (hr == D3DERR_DEVICENOTRESET)
                ResetDevice();
            g_DeviceLost = false;
        }

        // Handle window resize (we don't resize directly in the WM_SIZE handler)
        if (g_ResizeWidth != 0 && g_ResizeHeight != 0)
        {
            g_d3dpp.BackBufferWidth = g_ResizeWidth;
            g_d3dpp.BackBufferHeight = g_ResizeHeight;
            g_ResizeWidth = g_ResizeHeight = 0;
            ResetDevice();
        }

        // Start the Dear ImGui frame
        ImGui_ImplDX9_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        // Get the size and position of the main window
        RECT rect;
        GetClientRect(hwnd, &rect);
        POINT topLeft = { rect.left, rect.top };
        ClientToScreen(hwnd, &topLeft);
        float window_width = static_cast<float>(rect.right - rect.left);
        float window_height = static_cast<float>(rect.bottom - rect.top);

        // Password Cracker UI
        {
            static char hash_input[256] = "";
            static char password_output[256] = "";
            static char md5_file_path[256] = "";
            static char sha256_file_path[256] = "";
            static std::string md5_file_contents = "";
            static std::string sha256_file_contents = "";
            static bool show_file_contents_window = false;
            static std::string md5_filename = "";
            static std::string sha256_filename = "";

            ImGui::SetNextWindowPos(ImVec2(static_cast<float>(topLeft.x), static_cast<float>(topLeft.y)));
            ImGui::SetNextWindowSize(ImVec2(window_width, window_height / 4)); // Decrease the height of the Password Cracker window by 2x
            ImGui::Begin("Password Cracker");

            ImGui::Text("Enter your hash:");                           // Display some text
            ImGui::InputText("##hash_input", hash_input, IM_ARRAYSIZE(hash_input)); // Input text field for hash

            if (ImGui::Button("Crack MD5 Hash"))                       // Button to crack MD5 hash
            {
                if (strlen(md5_file_path) > 0) {
                    std::string password = findPasswordInFile(md5_file_path, hash_input);
                    strcpy_s(password_output, password.c_str());
                }
                else {
                    strcpy_s(password_output, "No MD5 file selected");
                }
            }

            ImGui::SameLine();
            if (ImGui::Button("Crack SHA256 Hash"))                    // Button to crack SHA256 hash
            {
                if (strlen(sha256_file_path) > 0) {
                    std::string password = findPasswordInFile(sha256_file_path, hash_input);
                    strcpy_s(password_output, password.c_str());
                }
                else {
                    strcpy_s(password_output, "No SHA256 file selected");
                }
            }

            ImGui::Text("Password: %s", password_output);              // Display the cracked password

            ImGui::Text("MD5 .txt File: %s", md5_filename.c_str());              // Display the MD5 filename
            ImGui::Text("SHA256 .txt File: %s", sha256_filename.c_str());        // Display the SHA256 filename

            if (ImGui::Button("Import MD5 File"))                          // Button to import MD5 file
            {
                std::string selected_file = openFileDialog();
                if (!selected_file.empty()) {
                    strcpy_s(md5_file_path, selected_file.c_str());
                    md5_file_contents = readFileContents(md5_file_path);
                    md5_filename = selected_file.substr(selected_file.find_last_of("/\\") + 1);
                    show_file_contents_window = true;
                    ImGui::SetWindowFocus("File Contents");
                }
            }

            ImGui::SameLine();
            if (ImGui::Button("Import SHA256 File"))                          // Button to import SHA256 file
            {
                std::string selected_file = openFileDialog();
                if (!selected_file.empty()) {
                    strcpy_s(sha256_file_path, selected_file.c_str());
                    sha256_file_contents = readFileContents(sha256_file_path);
                    sha256_filename = selected_file.substr(selected_file.find_last_of("/\\") + 1);
                    show_file_contents_window = true;
                    ImGui::SetWindowFocus("File Contents");
                }
            }

            ImGui::End();

            if (show_file_contents_window) {
                ImGui::SetNextWindowPos(ImVec2(static_cast<float>(topLeft.x), static_cast<float>(topLeft.y) + window_height / 4)); // Position below the Password Cracker window
                ImGui::SetNextWindowSize(ImVec2(window_width, window_height * 3 / 4)); // Increase the height of the File Contents window by 2x
                ImGui::Begin("File Contents", &show_file_contents_window);

                if (ImGui::BeginTabBar("FileContentsTabBar")) {
                    if (ImGui::BeginTabItem("MD5 File")) {
                        ImGui::InputTextMultiline("##md5_file_contents", &md5_file_contents[0], md5_file_contents.size() + 1, ImVec2(-FLT_MIN, -FLT_MIN), ImGuiInputTextFlags_ReadOnly);
                        ImGui::EndTabItem();
                    }
                    if (ImGui::BeginTabItem("SHA256 File")) {
                        ImGui::InputTextMultiline("##sha256_file_contents", &sha256_file_contents[0], sha256_file_contents.size() + 1, ImVec2(-FLT_MIN, -FLT_MIN), ImGuiInputTextFlags_ReadOnly);
                        ImGui::EndTabItem();
                    }
                    ImGui::EndTabBar();
                }

                ImGui::End();
            }
        }

        // Rendering
        ImGui::EndFrame();
        g_pd3dDevice->SetRenderState(D3DRS_ZENABLE, FALSE);
        g_pd3dDevice->SetRenderState(D3DRS_ALPHABLENDENABLE, FALSE);
        g_pd3dDevice->SetRenderState(D3DRS_SCISSORTESTENABLE, FALSE);
        D3DCOLOR clear_col_dx = D3DCOLOR_RGBA((int)(clear_color.x * clear_color.w * 255.0f), (int)(clear_color.y * clear_color.w * 255.0f), (int)(clear_color.z * clear_color.w * 255.0f), (int)(clear_color.w * 255.0f));
        g_pd3dDevice->Clear(0, nullptr, D3DCLEAR_TARGET | D3DCLEAR_ZBUFFER, clear_col_dx, 1.0f, 0);
        if (g_pd3dDevice->BeginScene() >= 0)
        {
            ImGui::Render();
            ImGui_ImplDX9_RenderDrawData(ImGui::GetDrawData());
            g_pd3dDevice->EndScene();
        }

        // Update and Render additional Platform Windows
        if (io.ConfigFlags & ImGuiConfigFlags_ViewportsEnable)
        {
            ImGui::UpdatePlatformWindows();
            ImGui::RenderPlatformWindowsDefault();
        }

        HRESULT result = g_pd3dDevice->Present(nullptr, nullptr, nullptr, nullptr);
        if (result == D3DERR_DEVICELOST)
            g_DeviceLost = true;
    }

    // Cleanup
    ImGui_ImplDX9_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();

    CleanupDeviceD3D();
    ::DestroyWindow(hwnd);
    ::UnregisterClassW(wc.lpszClassName, wc.hInstance);

    return 0;
}

// Helper functions
bool CreateDeviceD3D(HWND hWnd)
{
    if ((g_pD3D = Direct3DCreate9(D3D_SDK_VERSION)) == nullptr)
        return false;

    // Create the D3DDevice
    ZeroMemory(&g_d3dpp, sizeof(g_d3dpp));
    g_d3dpp.Windowed = TRUE;
    g_d3dpp.SwapEffect = D3DSWAPEFFECT_DISCARD;
    g_d3dpp.BackBufferFormat = D3DFMT_UNKNOWN; // Need to use an explicit format with alpha if needing per-pixel alpha composition.
    g_d3dpp.EnableAutoDepthStencil = TRUE;
    g_d3dpp.AutoDepthStencilFormat = D3DFMT_D16;
    g_d3dpp.PresentationInterval = D3DPRESENT_INTERVAL_ONE;           // Present with vsync
    //g_d3dpp.PresentationInterval = D3DPRESENT_INTERVAL_IMMEDIATE;   // Present without vsync, maximum unthrottled framerate
    if (g_pD3D->CreateDevice(D3DADAPTER_DEFAULT, D3DDEVTYPE_HAL, hWnd, D3DCREATE_HARDWARE_VERTEXPROCESSING, &g_d3dpp, &g_pd3dDevice) < 0)
        return false;

    return true;
}

void CleanupDeviceD3D()
{
    if (g_pd3dDevice) { g_pd3dDevice->Release(); g_pd3dDevice = nullptr; }
    if (g_pD3D) { g_pD3D->Release(); g_pD3D = nullptr; }
}

void ResetDevice()
{
    ImGui_ImplDX9_InvalidateDeviceObjects();
    HRESULT hr = g_pd3dDevice->Reset(&g_d3dpp);
    if (hr == D3DERR_INVALIDCALL)
        IM_ASSERT(0);
    ImGui_ImplDX9_CreateDeviceObjects();
}

#ifndef WM_DPICHANGED
#define WM_DPICHANGED 0x02E0 // From Windows SDK 8.1+ headers
#endif

// Forward declare message handler from imgui_impl_win32.cpp
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

// Win32 message handler
LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
        return true;

    switch (msg)
    {
    case WM_SIZE:
        if (wParam == SIZE_MINIMIZED)
            return 0;
        g_ResizeWidth = (UINT)LOWORD(lParam); // Queue resize
        g_ResizeHeight = (UINT)HIWORD(lParam);
        return 0;
    case WM_SYSCOMMAND:
        if ((wParam & 0xfff0) == SC_KEYMENU) // Disable ALT application menu
            return 0;
        break;
    case WM_DESTROY:
        ::PostQuitMessage(0);
        return 0;
    case WM_DPICHANGED:
        if (ImGui::GetIO().ConfigFlags & ImGuiConfigFlags_DpiEnableScaleViewports)
        {
            const RECT* suggested_rect = (RECT*)lParam;
            ::SetWindowPos(hWnd, nullptr, suggested_rect->left, suggested_rect->top, suggested_rect->right - suggested_rect->left, suggested_rect->bottom - suggested_rect->top, SWP_NOZORDER | SWP_NOACTIVATE);
        }
        break;
    }
    return ::DefWindowProcW(hWnd, msg, wParam, lParam);
}
