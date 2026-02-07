@{
    # Only check for errors and critical security issues
    # Warnings about Write-Host and plural nouns are acceptable for this project

    Severity = @('Error', 'Warning')

    # Rules to exclude (acceptable for this type of application)
    ExcludeRules = @(
        # Write-Host is intentional for colored console output in test script
        'PSAvoidUsingWriteHost',

        # Plural nouns are more descriptive for our functions (Get-InstalledBrowsers, etc.)
        'PSUseSingularNouns',

        # We don't need ShouldProcess for this security tool
        'PSUseShouldProcessForStateChangingFunctions',

        # Write-Log is our custom function, not overwriting the cmdlet
        'PSAvoidOverwritingBuiltInCmdlets'
    )

    # Rules to include with specific settings
    Rules = @{
        PSAvoidUsingEmptyCatchBlock = @{
            Enable = $true
        }

        PSAvoidAssignmentToAutomaticVariable = @{
            Enable = $true
        }

        PSUseDeclaredVarsMoreThanAssignments = @{
            Enable = $true
        }
    }
}
