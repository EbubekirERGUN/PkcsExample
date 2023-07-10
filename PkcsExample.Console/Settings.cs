using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;

namespace PkcsExample.Console;

public class Settings
{
    public static Pkcs11InteropFactories Factories = new Pkcs11InteropFactories();
    
    public static string Pkcs11LibraryPath = @"C:\ProCrypt-KM3000\config\procryptoki.dll";  
    
    public static AppType AppType = AppType.MultiThreaded;
    
    public static string TokenSerial = null;
    
    public static string TokenLabel = null;
    
    public static string SecurityOfficerPin = @"1111";
    
    public static string NormalUserPin = @"1111";
    
    public static string ApplicationName = @"Pkcs11Interop";

    public static byte[] SecurityOfficerPinArray = null;
    
    public static byte[] NormalUserPinArray = null;
    
    public static byte[] ApplicationNameArray = null;
    
    public static string PrivateKeyUri = null;


    public Settings()
    {
        SecurityOfficerPinArray = ConvertUtils.Utf8StringToBytes(SecurityOfficerPin);
        NormalUserPinArray = ConvertUtils.Utf8StringToBytes(NormalUserPin);
        ApplicationNameArray = ConvertUtils.Utf8StringToBytes(ApplicationName);
        
        Pkcs11UriBuilder pkcs11UriBuilder = new Pkcs11UriBuilder();
        pkcs11UriBuilder.ModulePath = Pkcs11LibraryPath;
        pkcs11UriBuilder.Serial = TokenSerial;
        pkcs11UriBuilder.Token = TokenLabel;
        pkcs11UriBuilder.PinValue = NormalUserPin;
        pkcs11UriBuilder.Type = CKO.CKO_PRIVATE_KEY;
        pkcs11UriBuilder.Object = ApplicationName;
        PrivateKeyUri = pkcs11UriBuilder.ToString();
    }
}