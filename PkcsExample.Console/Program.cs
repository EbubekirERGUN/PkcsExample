using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using PkcsExample.Console;

Settings settings = new Settings();

IPkcs11Library pkcs11Library =
    Settings.Factories.Pkcs11LibraryFactory.LoadPkcs11Library(Settings.Factories, Settings.Pkcs11LibraryPath,
        Settings.AppType);

// ----------------Kod Test Alanı------------
GenerateKeyPairTest();
// --------------

/// GetInfo .
void BasicGetInfoTest()
{
    ILibraryInfo libraryInfo = pkcs11Library.GetInfo();
}

//GetAttibuteValue
void GetAttributeValueTest()
{
    List<ISlot> slots = pkcs11Library.GetSlotList(SlotsType.WithOrWithoutTokenPresent);
    ISession session = slots[0].OpenSession(SessionType.ReadWrite);
    session.Login(CKU.CKU_USER, Settings.NormalUserPin);

    IObjectHandle objectHandle = GetObject("iTextTestRoot", session, false);


    List<CKA> attributes = new List<CKA>();
    attributes.Add(CKA.CKA_LABEL);
    attributes.Add(CKA.CKA_VALUE);
    attributes.Add(CKA.CKA_CLASS);

    List<IObjectAttribute> objectAttributes = session.GetAttributeValue(objectHandle, attributes);
    var certificate = objectAttributes[1].GetValueAsString();
}

//Encrypt and Decrypt
void EncryptAndDecryptSinglePartTest()
{
    List<ISlot> slots = pkcs11Library.GetSlotList(SlotsType.WithOrWithoutTokenPresent);
    ISession session = slots[0].OpenSession(SessionType.ReadWrite);
    session.Login(CKU.CKU_USER, Settings.NormalUserPin);

    IObjectHandle keyLabel = GetObject("signCertRsa01", session, false);
    IMechanism mechanism = session.Factories.MechanismFactory.Create(CKM.CKM_RSA_PKCS);
    byte[] sourceData = ConvertUtils.Utf8StringToBytes("Hello world");
    byte[] encryptedData = session.Encrypt(mechanism, keyLabel, sourceData);
    IObjectHandle keyLabelV2 = GetObject("signCertRsa01", session, true);
    byte[] decryptedData = session.Decrypt(mechanism, keyLabelV2, encryptedData);
}

//Sign And Verify
void SignAndVerifySinglePartTest()
{
    List<ISlot> slots = pkcs11Library.GetSlotList(SlotsType.WithOrWithoutTokenPresent);
    ISession session = slots[0].OpenSession(SessionType.ReadWrite);
    session.Login(CKU.CKU_USER, Settings.NormalUserPin);
    IObjectHandle keyLabelPrivate = GetObject("signCertRsa01", session, true);
    IMechanism mechanism = session.Factories.MechanismFactory.Create(CKM.CKM_RSA_PKCS);
    byte[] sourceData = ConvertUtils.Utf8StringToBytes("Hello world");
    byte[] signature = session.Sign(mechanism, keyLabelPrivate, sourceData);


    IObjectHandle keyLabelPublic = GetObject("signCertRsa01", session, false);

    bool isValid = false;
    session.Verify(mechanism, keyLabelPublic, sourceData, signature, out isValid);
}

//GetAll
void FindAllObjectsTest()
{
    List<ISlot> slots = pkcs11Library.GetSlotList(SlotsType.WithOrWithoutTokenPresent);
    ISession session = slots[0].OpenSession(SessionType.ReadWrite);
    session.Login(CKU.CKU_USER, Settings.NormalUserPin);

    List<IObjectAttribute> objectAttributes = new List<IObjectAttribute>();
    objectAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true));
    // objectAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS,CKO.CKO_CERTIFICATE ));
    List<IObjectHandle> foundObjects = session.FindAllObjects(objectAttributes);
}

/// GenerateRandom.
void GenerateRandomTest()
{
    List<ISlot> slots = pkcs11Library.GetSlotList(SlotsType.WithOrWithoutTokenPresent);
    ISession session = slots[0].OpenSession(SessionType.ReadWrite);
    byte[] randomData = session.GenerateRandom(16);
}


/// C_GenerateRandom test.
void BasicWrapAndUnwrapKeyTest()
{
    List<ISlot> slots = pkcs11Library.GetSlotList(SlotsType.WithOrWithoutTokenPresent);
    ISession session = slots[0].OpenSession(SessionType.ReadWrite);
    session.Login(CKU.CKU_USER, Settings.NormalUserPin);

    IObjectHandle publicKey = GetObject("signCertRsa01", session, false);
    IObjectHandle privateKey = GetObject("signCertRsa01", session, true);

    IObjectHandle secretKey = GetObject("aes128", session, true);

    IMechanism mechanism = session.Factories.MechanismFactory.Create(CKM.CKM_RSA_PKCS);

    byte[] wrappedKey = session.WrapKey(mechanism, publicKey, secretKey);

    List<IObjectAttribute> objectAttributes = new List<IObjectAttribute>();
    objectAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY));
    objectAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_DES3));
    objectAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ENCRYPT, true));
    objectAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_DECRYPT, true));
    objectAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_DERIVE, true));
    objectAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_EXTRACTABLE, true));

    IObjectHandle unwrappedKey = session.UnwrapKey(mechanism, privateKey, wrappedKey, objectAttributes);
}

//GenerateKey
void GenerateKeyTest()
{
    List<ISlot> slots = pkcs11Library.GetSlotList(SlotsType.WithOrWithoutTokenPresent);
    ISession session = slots[0].OpenSession(SessionType.ReadWrite);
    session.Login(CKU.CKU_USER, Settings.NormalUserPin);

    List<IObjectAttribute> objectAttributes = new List<IObjectAttribute>();
    objectAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY));
    objectAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_DES3));
    objectAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ENCRYPT, true));
    objectAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_DECRYPT, true));
    objectAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true));
    objectAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, "EbubekirTest"));

    IMechanism mechanism = session.Factories.MechanismFactory.Create(CKM.CKM_DES3_KEY_GEN);
    IObjectHandle objectHandle = session.GenerateKey(mechanism, objectAttributes);
}


//GenerateKeyPair
void GenerateKeyPairTest()
{
    List<ISlot> slots = pkcs11Library.GetSlotList(SlotsType.WithOrWithoutTokenPresent);
    ISession session = slots[0].OpenSession(SessionType.ReadWrite);
    session.Login(CKU.CKU_USER, Settings.NormalUserPin);

    byte[] ckaId = session.GenerateRandom(20);

    // Prepare attribute template of new public key
    List<IObjectAttribute> publicKeyAttributes = new List<IObjectAttribute>();
    publicKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true));
    publicKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, false));
    publicKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, "EbubekirKeyPairTest"));
    publicKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ID, ckaId));
    publicKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ENCRYPT, true));
    publicKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_VERIFY, true));
    publicKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_VERIFY_RECOVER, true));
    publicKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_WRAP, true));
    publicKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_MODULUS_BITS, 1024));

    publicKeyAttributes.Add(
        session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PUBLIC_EXPONENT, new byte[] { 0x01, 0x00, 0x01 }));

    // Prepare attribute template of new private key
    List<IObjectAttribute> privateKeyAttributes = new List<IObjectAttribute>();
    privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true));
    privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, true));
    privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, "EbubekirKeyPairTest"));
    privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ID, ckaId));
    privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_SENSITIVE, true));
    privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_DECRYPT, true));
    privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_SIGN, true));
    privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_SIGN_RECOVER, true));
    privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_UNWRAP, true));
    
    IMechanism mechanism = session.Factories.MechanismFactory.Create(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN);
    
    IObjectHandle publicKeyHandle = null;
    IObjectHandle privateKeyHandle = null;
    session.GenerateKeyPair(mechanism, publicKeyAttributes, privateKeyAttributes, out publicKeyHandle, out privateKeyHandle);
}


IObjectHandle GetObject(string keyLabel, ISession session, bool isPrivateObject)
{
    List<IObjectAttribute> objectAttributes = new List<IObjectAttribute>();
    objectAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, keyLabel));
    objectAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true));
    objectAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, isPrivateObject));


    session.FindObjectsInit(objectAttributes);
    List<IObjectHandle> foundObjects = session.FindObjects(1);
    session.FindObjectsFinal();
    if (foundObjects.Count == 0)
        throw new Exception("Key Not Found");
    return foundObjects[0];
}


//cihaz bağlantısını keser.
pkcs11Library.Dispose();