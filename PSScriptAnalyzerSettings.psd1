@{
    # Run default rules except those suppressed below
    IncludeDefaultRules = $true

    # Exclude test files and build script from analysis
    ExcludeRules = @(
        # Module uses Add-Type for C# compilation — this is intentional
        'PSAvoidUsingInvokeExpression'
    )

    Rules = @{
        # Allow cmdlets that change state without ShouldProcess on internal/private helpers
        PSUseShouldProcessForStateChangingFunctions = @{
            Enable = $true
        }

        # Enforce approved verbs
        PSUseApprovedVerbs = @{
            Enable = $true
        }

        # Require compatible syntax for PS 5.1+
        PSUseCompatibleSyntax = @{
            Enable         = $true
            TargetVersions = @('5.1', '7.0')
        }
    }
}
