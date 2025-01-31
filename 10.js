Java.perform(function () {
    var Build = Java.use("android.os.Build");
    var TelephonyManager = Java.use("android.telephony.TelephonyManager");
    var WifiInfo = Java.use("android.net.wifi.WifiInfo");
    var SettingsSecure = Java.use("android.provider.Settings$Secure");
    var UUID = Java.use("java.util.UUID");

    // 伪造设备硬件信息
    Build.MODEL.value = "Pixel 5";
    Build.MANUFACTURER.value = "Google";
    Build.BRAND.value = "Google";
    Build.DEVICE.value = "redfin";
    Build.PRODUCT.value = "redfin";
    Build.HARDWARE.value = "redfin";
    Build.SERIAL.value = "ABC123XYZ";

    // 伪造 IMEI
    TelephonyManager.getImei.overload().implementation = function () {
        return "123456789012345";
    };

    // 伪造 IMSI
    TelephonyManager.getSubscriberId.overload().implementation = function () {
        return "310260000000000";
    };

    // 伪造 SIM 序列号
    TelephonyManager.getSimSerialNumber.overload().implementation = function () {
        return "89014103211118510720";
    };

    // 伪造 Android ID
  /*  SettingsSecure.getString.overload(
        "android.content.ContentResolver",
        "java.lang.String"
    ).implementation = function (resolver, name) {
        if (name === SettingsSecure.ANDROID_ID.value) {
            return "9774d56d682e549c";
        }
        return this.getString(resolver, name);
    };*/

    // 伪造 WiFi MAC 地址
    WifiInfo.getMacAddress.implementation = function () {
        return "00:11:22:33:44:55";
    };

    // 伪造设备唯一标识符（UUID）
    UUID.randomUUID.implementation = function () {
        return UUID.fromString("123e4567-e89b-12d3-a456-426614174000");
    };

    console.log("设备信息伪造已应用");
});