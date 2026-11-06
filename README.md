# App Internet Switch

A Windows desktop utility for blocking or allowing internet access per selected application.

## Download

Open the **Actions** tab and select the latest successful **Build Windows EXE** run. Download the `AppInternetSwitch-Windows` artifact and extract `AppInternetSwitch.exe`.

## Use

1. Run `AppInternetSwitch.exe`.
2. Approve the Windows Administrator prompt.
3. Choose **Add app (.exe)** and select the application's executable.
4. Select the app and choose **Turn internet OFF** or **Turn internet ON**.

The app uses Windows Defender Firewall rules for inbound and outbound traffic. The app list is saved in `%APPDATA%\AppInternetSwitch\apps.json`.

## Notes

- Windows 10/11.
- Administrator permission is required.
- Some applications use separate helper processes; add those executables too if needed.
- Removing an entry also deletes the firewall rules created by this utility.
