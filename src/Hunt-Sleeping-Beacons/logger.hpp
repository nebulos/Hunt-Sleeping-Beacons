#ifndef LOGGER_HPP
#define LOGGER_HPP

#include "phnt.h"
#include <stdio.h>
#include <iostream>
#include <string>
#include <curl/curl.h> // Include libcurl for making HTTP requests

#include "detection.hpp"
#include "process.hpp"

namespace hsb::logger {

    class logger {

        using detection = hsb::containers::detections::detection;
        using process = hsb::containers::process;

    private:

        logger() = delete;
        static inline bool cmdline_;
        static inline const std::string n8n_webhook_url_ = "https://my-n8n-instance.com/webhook/your-webhook-path"; // Hard-coded n8n webhook URL (bad idea)

        static void send_to_n8n(const std::string& data) {
            CURL* curl;
            CURLcode res;
            curl_global_init(CURL_GLOBAL_DEFAULT);
            curl = curl_easy_init();
            if (curl) {
                curl_easy_setopt(curl, CURLOPT_URL, n8n_webhook_url_.c_str());
                curl_easy_setopt(curl, CURLOPT_POST, 1L);
                curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data.c_str());

                res = curl_easy_perform(curl);
                if (res != CURLE_OK) {
                    std::cerr << "curl_easy_perform() failed: " << curl_easy_strerror(res) << std::endl;
                }

                curl_easy_cleanup(curl);
            }
            curl_global_cleanup();
        }

    public:

        static void init(bool cmdline) {
            HANDLE h;
            DWORD mode;

            h = GetStdHandle(STD_OUTPUT_HANDLE);
            GetConsoleMode(h, &mode);
            SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);

            cmdline_ = cmdline;
        }

        static void logo(void) {
            std::wstring logo = 
                L" _   _    _____   ______\r\n"
                L"| | | |  /  ___|  | ___ \\\r\n"
                L"| |_| |  \\ `--.   | |_/ /\r\n"
                L"|  _  |   `--. \\  | ___ \\\r\n"
                L"| | | |  /\\__/ /  | |_/ /\r\n"
                L"\\_| |_/  \\____/   \\____/\r\n"
                L"\r\n"
                L"Hunt-Sleeping-Beacons | @thefLinkk\r\n"
                L"\r\n";
            std::wcout << logo;
            send_to_n8n(std::string(logo.begin(), logo.end())); // Send to n8n
        }

        static void help(void) {
            std::wstring help_message = 
                L"\n-p / --pid {PID}\n"
                L"\n--dotnet | Set to also include dotnet processes. ( Prone to false positivies )\n"
                L"--commandline | Enables output of cmdline for suspicious processes\n"
                L"-h / --help | Prints this message?\n"
                L"\n";
            std::wcout << help_message;
            send_to_n8n(std::string(help_message.begin(), help_message.end())); // Send to n8n
            exit(0);
        }

        static void print_suspicious_process(process* process) {
            std::wstring msg = std::format(L"\033[36` ▋
