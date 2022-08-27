<?php
require_once 'xmlseclibs/xmlseclibs.php';
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;

// certificate file locations
$public_certif = 'uidai_auth_stage.cer';
$stag_sign_file = 'Staging_Signature_PrivateKey.p12';

// set variables
$aadhaar_no = '999999990019';
$api_version = "2.5";
$asa_license_key = "MMxNu7a6589B5x5RahDW-zNP7rhGbZb5HsTRwbi-VVNxkoFmkHGmYKM";
$lk = "MBni88mRNM18dKdiVyDYCuddwXEQpl68dZAGBQ2nsOlGMzC9DkOVL5s";
$ac = "public";
$sa = "public";
$tid = "public";
$txn = "AuthDemoClient:public:".date("Ymdhms");
$ts = date('Y-m-d').'T'.date('H:i:s');

// PID Block
$pid_block='<?xml version="1.0"?><ns2:Pid ts="'.$ts.'" xmlns:ns2="http://www.uidai.gov.in/authentication/uid-auth-request-data/1.0"><ns2:Demo><ns2:Pi ms="E" mv="100" name="Shivshankar Choudhury"/></ns2:Demo></ns2:Pid>';

// generate aes-256 session key
$session_key = openssl_random_pseudo_bytes(32);


// generate auth xml
$auth_xml = '<?xml version="1.0" encoding="UTF-8"?><Auth uid="'.$aadhaar_no.'" ac="'.$ac.'" lk="'.$lk.'" sa="'.$sa.'" tid="'.$tid.'" txn="'.$txn.'" ver="'.$api_version.'" xmlns="http://www.uidai.gov.in/authentication/uid-auth-request/1.0" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><Uses bio="n" otp="n" pa="n" pfa="n" pi="y" pin="n"/><Meta fdc="NA" idc="NA" lot="P" lov="560094" pip="NA" udc="1122"/><Skey ci="'.certif_expire().'">'.encrypt_session_key($session_key).'</Skey><Data type="X">'.encrypt_pid($pid_block, $session_key).'</Data><Hmac>'.calculate_hmac($pid_block, $session_key).'</Hmac></Auth>';

//echo $auth_xml;
 //die();
// $xml=simplexml_load_string($auth_xml) or die("Error: Cannot create object");
//print_r($xml);

// xmldsig the auth xml
$doc = new DOMDocument();
$doc->loadXML($auth_xml);
$objDSig = new XMLSecurityDSig();
$objDSig->setCanonicalMethod(XMLSecurityDSig::C14N);
$objDSig->addReference(
    $doc,
    XMLSecurityDSig::SHA256,
    array(
        'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
        'http://www.w3.org/2001/10/xml-exc-c14n#'
    ),
    array('force_uri' => true)
);
$objKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, array('type'=>'private'));
openssl_pkcs12_read(file_get_contents($stag_sign_file), $key, "public");
$objKey->loadKey($key["pkey"]);
$objDSig->add509Cert($key["cert"]);
$objDSig->sign($objKey, $doc->documentElement);


// make a request to uidai
$ch = curl_init("http://auth.uidai.gov.in/$api_version/public/".$aadhaar_no[0]."/".$aadhaar_no[0]."/$asa_license_key");
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
curl_setopt($ch, CURLOPT_POST, 1);
curl_setopt($ch, CURLOPT_POSTFIELDS, $doc->saveXML());
curl_setopt($ch, CURLOPT_HTTPHEADER, array(
  "Accept: application/xml",
  "Content-Type: application/xml"
));
echo "\nRequest XML\n";
echo $doc->saveXML();
echo "\n\n";
echo "Response from UIDAI\n";
echo htmlspecialchars_decode(curl_exec($ch));



function encrypt_pid($pid_block, $session_key)
{
    return encrypt_by_session_key($pid_block, $session_key);
}

function encrypt_by_session_key($data, $session_key)
{
    global $public_certif;
    $fp=fopen($public_certif, "r");
    $pub_key_string=fread($fp,8192);
    openssl_public_encrypt($data, $encrypted_data, $pub_key_string, OPENSSL_PKCS1_PADDING);
    return $encrypted_data;
    }
function generateRandomString($length = 32) {
    $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    $charactersLength = strlen($characters);
    $randomString = '';
    for ($i = 0; $i < $length; $i++) {
        $randomString .= $characters[rand(0, $charactersLength - 1)];
    }
    return $randomString;

}

function calculate_hmac($data, $session_key)
{
    return encrypt_by_session_key(hash('sha256', $data, true), $session_key);
}

function certif_expire()
{
    global $public_certif;
    $certinfo = openssl_x509_parse(file_get_contents($public_certif));
    return date('Ymd', $certinfo['validTo_time_t']);
}

function encrypt_session_key($session_key)
{
    global $public_certif;
    $pub_key = openssl_pkey_get_public(file_get_contents($public_certif));
    $keyData = openssl_pkey_get_details($pub_key);
    openssl_public_encrypt($session_key, $encrypted_session_key, $keyData['key'], OPENSSL_PKCS1_PADDING);
    return base64_encode($encrypted_session_key);
}
