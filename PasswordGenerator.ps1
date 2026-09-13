<#
.SYNOPSIS
    Creates a graphical utility for generating cryptographically secure passwords.

.DESCRIPTION
    This script is intended for Windows PowerShell 5.1. It creates a WinForms window
    that generates passwords from English letters, digits, and optional special characters.
#>

# Loads the .NET assemblies required to create the Windows Forms interface.
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Enables strict mode to detect accidental use of undefined variables.
Set-StrictMode -Version Latest

<#
.SYNOPSIS
    Returns one cryptographically secure random index.

.DESCRIPTION
    Uses a RandomNumberGenerator instance and rejection sampling, so every index from zero
    through Maximum - 1 has the same probability. This avoids the modulo bias that can occur
    when random bytes are reduced directly with the modulo operator.
#>
function Get-CryptoRandomIndex {
    param(
        # Specifies the exclusive upper bound for the returned index.
        [Parameter(Mandatory = $true)]
        [ValidateRange(1, [int]::MaxValue)]
        [int]$Maximum,

        # Specifies the cryptographic random-number generator to use.
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.RandomNumberGenerator]$RandomNumberGenerator
    )

    # Creates a four-byte buffer for one unsigned 32-bit random value.
    $randomBytes = New-Object byte[] 4
    # Calculates the size of the full UInt32 value range.
    $valueRange = [uint64][uint32]::MaxValue + 1
    # Calculates the first rejected value to keep the remaining range divisible by Maximum.
    $rejectionLimit = $valueRange - ($valueRange % [uint64]$Maximum)

    do {
        # Fills the byte buffer with cryptographically secure random bytes.
        $RandomNumberGenerator.GetBytes($randomBytes)
        # Converts the random bytes to an unsigned 32-bit integer.
        $randomValue = [BitConverter]::ToUInt32($randomBytes, 0)
    } while ([uint64]$randomValue -ge $rejectionLimit)

    # Returns an unbiased zero-based index within the requested range.
    return [int]([uint64]$randomValue % [uint64]$Maximum)
}

<#
.SYNOPSIS
    Creates a cryptographically secure password.

.DESCRIPTION
    Builds a character set from English letters and digits, optionally adds special characters,
    optionally removes visually similar characters, and chooses every password character using
    a cryptographic random-number generator.
#>
function New-CryptographicPassword {
    param(
        # Specifies the number of characters in the generated password.
        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 300)]
        [int]$Length,

        # Omits special characters when this switch is present.
        [switch]$ExcludeSpecialCharacters,

        # Omits the similar characters 0, O, 1, I, l, 5, S, 2, Z, 8, B when this switch is present.
        [switch]$ExcludeSimilarCharacters
    )

    # Defines the English lowercase letters, uppercase letters, and digits.
    $characters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'

    if (-not $ExcludeSpecialCharacters) {
        # Adds a conservative set of special characters that works in most password fields.
        $characters += '!@#$%^&*()-_=+[]{};:,.?'
    }

    if ($ExcludeSimilarCharacters) {
        # Removes the explicitly requested visually similar characters from the available set.
        $characters = $characters -replace '[0O1Il5S2Z8B]', ''
    }

    if ([string]::IsNullOrEmpty($characters)) {
        # Stops execution if no characters remain available for password generation.
        throw 'The selected options left no available characters.'
    }

    # Allocates a character array of the requested password length.
    $passwordCharacters = New-Object char[] $Length
    # Creates the cryptographic source used for all password characters.
    $randomNumberGenerator = [System.Security.Cryptography.RandomNumberGenerator]::Create()

    try {
        for ($index = 0; $index -lt $Length; $index++) {
            # Obtains a cryptographically secure position in the available character set.
            $characterIndex = Get-CryptoRandomIndex -Maximum $characters.Length -RandomNumberGenerator $randomNumberGenerator
            # Writes the selected character to the current password position.
            $passwordCharacters[$index] = $characters[$characterIndex]
        }
    }
    finally {
        # Releases the cryptographic provider even if password generation fails.
        $randomNumberGenerator.Dispose()
    }

    # Joins the selected characters into the completed password string.
    return -join $passwordCharacters
}

<#
.SYNOPSIS
    Loads the password-generator settings from an .env file.

.DESCRIPTION
    Reads the supported key-value pairs from the specified .env file. Missing, malformed, or
    out-of-range values are replaced with safe default settings.
#>
function Get-PasswordGeneratorSettings {
    param(
        # Specifies the full path of the .env settings file to read.
        [Parameter(Mandatory = $true)]
        [string]$SettingsFilePath
    )

    # Defines the settings used when the .env file is missing or contains invalid values.
    $settings = @{
        PasswordLength = 10
        ExcludeSpecialCharacters = $true
        ExcludeSimilarCharacters = $true
    }

    # Returns the default settings when the settings file has not yet been created.
    if (-not (Test-Path -LiteralPath $SettingsFilePath -PathType Leaf)) {
        return [pscustomobject]$settings
    }

    # Reads the .env file one line at a time using UTF-8 text handling.
    foreach ($settingLine in (Get-Content -LiteralPath $SettingsFilePath -Encoding UTF8)) {
        # Removes whitespace around the current setting line.
        $trimmedSettingLine = $settingLine.Trim()

        # Ignores blank lines, comments, and lines that are not key-value pairs.
        if ($trimmedSettingLine.Length -eq 0 -or $trimmedSettingLine.StartsWith('#') -or -not $trimmedSettingLine.Contains('=')) {
            continue
        }

        # Splits the line only at the first equals sign so values can contain later equals signs.
        $settingPair = $trimmedSettingLine -split '=', 2
        # Normalizes the setting key to make its comparison case-insensitive.
        $settingName = $settingPair[0].Trim().ToUpperInvariant()
        # Removes whitespace around the setting value.
        $settingValue = $settingPair[1].Trim()

        switch ($settingName) {
            'PASSWORD_LENGTH' {
                # Creates a variable that receives the parsed password length.
                $parsedPasswordLength = 0

                # Stores the value only when it is a supported password length.
                if ([int]::TryParse($settingValue, [ref]$parsedPasswordLength) -and $parsedPasswordLength -ge 1 -and $parsedPasswordLength -le 300) {
                    $settings.PasswordLength = $parsedPasswordLength
                }
            }
            'EXCLUDE_SPECIAL_CHARACTERS' {
                # Converts the .env Boolean literal into the corresponding checkbox value.
                switch ($settingValue.ToLowerInvariant()) {
                    'true' { $settings.ExcludeSpecialCharacters = $true }
                    'false' { $settings.ExcludeSpecialCharacters = $false }
                }
            }
            'EXCLUDE_SIMILAR_CHARACTERS' {
                # Converts the .env Boolean literal into the corresponding checkbox value.
                switch ($settingValue.ToLowerInvariant()) {
                    'true' { $settings.ExcludeSimilarCharacters = $true }
                    'false' { $settings.ExcludeSimilarCharacters = $false }
                }
            }
        }
    }

    # Returns the loaded settings as one object.
    return [pscustomobject]$settings
}

<#
.SYNOPSIS
    Saves the password-generator settings to an .env file.

.DESCRIPTION
    Writes the last selected password length and both checkbox values to the specified .env file
    in UTF-8 without a byte-order mark.
#>
function Save-PasswordGeneratorSettings {
    param(
        # Specifies the full path of the .env settings file to write.
        [Parameter(Mandatory = $true)]
        [string]$SettingsFilePath,

        # Specifies the password length to store.
        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 300)]
        [int]$PasswordLength,

        # Specifies whether special characters are excluded.
        [Parameter(Mandatory = $true)]
        [bool]$ExcludeSpecialCharacters,

        # Specifies whether visually similar characters are excluded.
        [Parameter(Mandatory = $true)]
        [bool]$ExcludeSimilarCharacters
    )

    # Creates the .env lines that represent the current settings.
    $settingLines = @(
        '# Password Generator settings'
        "PASSWORD_LENGTH=$PasswordLength"
        "EXCLUDE_SPECIAL_CHARACTERS=$($ExcludeSpecialCharacters.ToString().ToLowerInvariant())"
        "EXCLUDE_SIMILAR_CHARACTERS=$($ExcludeSimilarCharacters.ToString().ToLowerInvariant())"
    )
    # Creates a UTF-8 encoding instance that does not add a byte-order mark to the .env file.
    $utf8WithoutBom = New-Object System.Text.UTF8Encoding($false)

    # Writes the settings lines to the .env file in the script folder.
    [System.IO.File]::WriteAllLines($SettingsFilePath, $settingLines, $utf8WithoutBom)
}

# Builds the .env settings file path in the same folder as this script.
$settingsFilePath = Join-Path -Path $PSScriptRoot -ChildPath '.env'
# Loads the settings that initialize the interface controls.
$settings = Get-PasswordGeneratorSettings -SettingsFilePath $settingsFilePath

# Creates the main application window.
$gui_MainForm = New-Object System.Windows.Forms.Form
$gui_MainForm.Text = 'Генератор криптостойких паролей'
$gui_MainForm.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen
$gui_MainForm.ClientSize = New-Object System.Drawing.Size(680, 265)
$gui_MainForm.MinimumSize = New-Object System.Drawing.Size(600, 265)
$gui_MainForm.Font = New-Object System.Drawing.Font('Segoe UI', 10)
$gui_MainForm.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
$gui_MainForm.MaximizeBox = $false

# Creates a table layout to align the interface controls.
$gui_Layout = New-Object System.Windows.Forms.TableLayoutPanel
$gui_Layout.Dock = [System.Windows.Forms.DockStyle]::Fill
$gui_Layout.Padding = New-Object System.Windows.Forms.Padding(16)
$gui_Layout.ColumnCount = 2
$gui_Layout.RowCount = 5
[void]$gui_Layout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
[void]$gui_Layout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
[void]$gui_Layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))
[void]$gui_Layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))
[void]$gui_Layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))
[void]$gui_Layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))
[void]$gui_Layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))

# Creates the label for the password-length selector.
$gui_LengthLabel = New-Object System.Windows.Forms.Label
$gui_LengthLabel.Text = 'Длина пароля:'
$gui_LengthLabel.AutoSize = $true
$gui_LengthLabel.Anchor = [System.Windows.Forms.AnchorStyles]::Left

# Creates the selector for a password length from 1 through 300 characters.
$gui_LengthSelector = New-Object System.Windows.Forms.NumericUpDown
$gui_LengthSelector.Minimum = 1
$gui_LengthSelector.Maximum = 300
$gui_LengthSelector.Value = $settings.PasswordLength
$gui_LengthSelector.Width = 100
$gui_LengthSelector.Anchor = [System.Windows.Forms.AnchorStyles]::Left

# Creates the checkbox that disables special characters.
$gui_ExcludeSpecialCharactersCheckBox = New-Object System.Windows.Forms.CheckBox
$gui_ExcludeSpecialCharactersCheckBox.Text = 'Генерировать без спецсимволов'
$gui_ExcludeSpecialCharactersCheckBox.AutoSize = $true
$gui_ExcludeSpecialCharactersCheckBox.Anchor = [System.Windows.Forms.AnchorStyles]::Left
# Selects exclusion of special characters by default.
$gui_ExcludeSpecialCharactersCheckBox.Checked = $settings.ExcludeSpecialCharacters

# Creates the checkbox that excludes the requested visually similar characters.
$gui_ExcludeSimilarCharactersCheckBox = New-Object System.Windows.Forms.CheckBox
$gui_ExcludeSimilarCharactersCheckBox.Text = 'Генерировать без похожих символов (0O1Il5S2Z8B)'
$gui_ExcludeSimilarCharactersCheckBox.AutoSize = $true
$gui_ExcludeSimilarCharactersCheckBox.Anchor = [System.Windows.Forms.AnchorStyles]::Left
# Selects exclusion of visually similar characters by default.
$gui_ExcludeSimilarCharactersCheckBox.Checked = $settings.ExcludeSimilarCharacters

# Creates the label for the generated-password text box.
$gui_PasswordLabel = New-Object System.Windows.Forms.Label
$gui_PasswordLabel.Text = 'Сгенерированный пароль:'
$gui_PasswordLabel.AutoSize = $true
$gui_PasswordLabel.Anchor = [System.Windows.Forms.AnchorStyles]::Left

# Creates the read-only text box that displays the generated password.
$gui_PasswordTextBox = New-Object System.Windows.Forms.TextBox
$gui_PasswordTextBox.ReadOnly = $true
$gui_PasswordTextBox.Multiline = $true
$gui_PasswordTextBox.ScrollBars = [System.Windows.Forms.ScrollBars]::Vertical
$gui_PasswordTextBox.Dock = [System.Windows.Forms.DockStyle]::Fill
$gui_PasswordTextBox.Font = New-Object System.Drawing.Font('Consolas', 10)

# Creates the button that generates a new password.
$gui_GenerateButton = New-Object System.Windows.Forms.Button
$gui_GenerateButton.Text = 'Сгенерировать пароль'
$gui_GenerateButton.AutoSize = $true
$gui_GenerateButton.Anchor = [System.Windows.Forms.AnchorStyles]::Right

# Creates the button that copies the displayed password to the clipboard.
$gui_CopyButton = New-Object System.Windows.Forms.Button
$gui_CopyButton.Text = 'Копировать'
$gui_CopyButton.AutoSize = $true
$gui_CopyButton.Anchor = [System.Windows.Forms.AnchorStyles]::Right
$gui_CopyButton.Enabled = $false

# Adds the length controls to the first layout row.
[void]$gui_Layout.Controls.Add($gui_LengthLabel, 0, 0)
[void]$gui_Layout.Controls.Add($gui_LengthSelector, 1, 0)
# Adds the special-character option to the second layout row.
[void]$gui_Layout.Controls.Add($gui_ExcludeSpecialCharactersCheckBox, 1, 1)
# Adds the similar-character option to the third layout row.
[void]$gui_Layout.Controls.Add($gui_ExcludeSimilarCharactersCheckBox, 1, 2)
# Adds the password controls to the fourth layout row.
[void]$gui_Layout.Controls.Add($gui_PasswordLabel, 0, 3)
[void]$gui_Layout.Controls.Add($gui_PasswordTextBox, 1, 3)

# Creates a panel that keeps the action buttons together in the final layout row.
$gui_ButtonPanel = New-Object System.Windows.Forms.FlowLayoutPanel
$gui_ButtonPanel.AutoSize = $true
$gui_ButtonPanel.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
$gui_ButtonPanel.FlowDirection = [System.Windows.Forms.FlowDirection]::RightToLeft
$gui_ButtonPanel.WrapContents = $false
$gui_ButtonPanel.Anchor = [System.Windows.Forms.AnchorStyles]::Right

# Adds the action buttons to the button panel.
[void]$gui_ButtonPanel.Controls.Add($gui_CopyButton)
[void]$gui_ButtonPanel.Controls.Add($gui_GenerateButton)
# Adds the action panel to the final layout row and spans both layout columns.
[void]$gui_Layout.Controls.Add($gui_ButtonPanel, 0, 4)
$gui_Layout.SetColumnSpan($gui_ButtonPanel, 2)

# Adds the layout to the main application window.
[void]$gui_MainForm.Controls.Add($gui_Layout)

# Creates or normalizes the .env settings file with the values currently used by the interface.
Save-PasswordGeneratorSettings -SettingsFilePath $settingsFilePath -PasswordLength ([int]$gui_LengthSelector.Value) -ExcludeSpecialCharacters $gui_ExcludeSpecialCharactersCheckBox.Checked -ExcludeSimilarCharacters $gui_ExcludeSimilarCharactersCheckBox.Checked

# Generates and displays a password when the generate button is clicked.
$gui_GenerateButton.Add_Click({
    try {
        # Calls the password-generation function with the settings selected in the interface.
        $gui_PasswordTextBox.Text = New-CryptographicPassword -Length ([int]$gui_LengthSelector.Value) -ExcludeSpecialCharacters:$gui_ExcludeSpecialCharactersCheckBox.Checked -ExcludeSimilarCharacters:$gui_ExcludeSimilarCharactersCheckBox.Checked
        # Enables copying after a password has been generated.
        $gui_CopyButton.Enabled = $true
        # Selects the generated password to make manual copying convenient.
        $gui_PasswordTextBox.SelectAll()
        $gui_PasswordTextBox.Focus()
    }
    catch {
        # Shows an error message if password generation cannot complete.
        [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, 'Ошибка генерации', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
})

# Copies the current password to the Windows clipboard when the copy button is clicked.
$gui_CopyButton.Add_Click({
    # Places the generated password on the clipboard.
    [System.Windows.Forms.Clipboard]::SetText($gui_PasswordTextBox.Text)
    # Updates the button caption to confirm the copy operation.
    $gui_CopyButton.Text = 'Скопировано'
})

# Restores the copy button caption when a newly generated password changes the displayed value.
$gui_GenerateButton.Add_Click({
    # Sets the standard caption for future copy operations.
    $gui_CopyButton.Text = 'Копировать'
})

# Saves the latest interface settings automatically when the application window is closing.
$gui_MainForm.Add_FormClosing({
    try {
        # Writes the last selected password length and checkbox states to the .env file.
        Save-PasswordGeneratorSettings -SettingsFilePath $settingsFilePath -PasswordLength ([int]$gui_LengthSelector.Value) -ExcludeSpecialCharacters $gui_ExcludeSpecialCharactersCheckBox.Checked -ExcludeSimilarCharacters $gui_ExcludeSimilarCharactersCheckBox.Checked
    }
    catch {
        # Notifies the user if the settings file cannot be saved.
        [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, 'Ошибка сохранения настроек', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
    }
})

# Sets the generate button as the default button for the Enter key.
$gui_MainForm.AcceptButton = $gui_GenerateButton
# Displays the application window and starts its message loop.
[void]$gui_MainForm.ShowDialog()
