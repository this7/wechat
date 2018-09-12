<?php
/**
 * this7 PHP Framework
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 *
 * @copyright 2016-2018 Yan TianZeng<qinuoyun@qq.com>
 * @license   http://www.opensource.org/licenses/mit-license.php MIT
 * @link      http://www.ub-7.com
 */
namespace this7\wechat\build;
use \Exception;

/**
 * 基础接口
 */
class base {

    private $appId;
    private $appSecret;

    public function __construct() {
        $this->appId     = C("wechat", "appId");
        $this->appSecret = C("wechat", "appSecret");
    }

    /**
     * 获取前端配置JS代码
     * @Author   Sean       Yan
     * @DateTime 2018-08-09
     * @return   [type]     [description]
     * 操作说明：
     * 框架需要安装View组件 并在View的配置文件 新增一条后置代码：wechat::jsSdkCode;
     * 例："rearcode": ["wechat::jsSdkCode"] 注意：切记请勿添加（）添加括号会导致运行出错
     */
    public function jsSdkCode($value = '') {
        $debug       = !DEBUG ? false : C("wechat", "debug");
        $jsApiList   = to_json(C("wechat", 'jsApiList'));
        $signPackage = $this->getSignPackage();
        $json        = to_json($signPackage);
        $JS          = <<<CODEJS
<script type="text/javascript">
var signPackage = '{$json}';
wx.config({
    debug: {$debug},
    appId: '{$signPackage["appId"]}',
    timestamp: {$signPackage["timestamp"]},
    nonceStr: '{$signPackage["nonceStr"]}',
    signature: '{$signPackage["signature"]}',
    jsApiList: {$jsApiList}
});
</script>
CODEJS;
        return $JS;
    }

    /**
     * 获取JSSDK签名
     * @Author   Sean       Yan
     * @DateTime 2018-08-09
     * @return   [type]     [description]
     */
    public function getSignPackage() {
        $jsapiTicket = $this->getJsApiTicket();

        #注意 URL 一定要动态获取，不能 hardcode.
        $protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off' || $_SERVER['SERVER_PORT'] == 443) ? "https://" : "http://";
        $url      = "$protocol$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]";

        $timestamp = time();
        $nonceStr  = $this->createNonceStr();

        #这里参数的顺序要按照 key 值 ASCII 码升序排序
        $string = "jsapi_ticket=$jsapiTicket&noncestr=$nonceStr&timestamp=$timestamp&url=$url";

        $signature = sha1($string);

        $signPackage = array(
            "appId"     => $this->appId,
            "nonceStr"  => $nonceStr,
            "timestamp" => $timestamp,
            "url"       => $url,
            "signature" => $signature,
            "rawString" => $string,
        );
        return $signPackage;
    }

    private function createNonceStr($length = 16) {
        $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        $str   = "";
        for ($i = 0; $i < $length; $i++) {
            $str .= substr($chars, mt_rand(0, strlen($chars) - 1), 1);
        }
        return $str;
    }

    /**
     * 用户Code获取
     * @Author   Sean       Yan
     * @DateTime 2018-08-09
     * @param    string     $url   [description]
     * @param    string     $scope [description]
     * @param    string     $scope [description]
     * @return   [type]            [description]
     */
    public function getUserCode($url = 'this7', $scope = 'snsapi_base') {
        #获取授权页面
        $redirect = urlencode(ROOT . '/' . md5('wechat') . "_wechat");
        $state    = urlencode($url);
        #提交URL地址
        $url = "https://open.weixin.qq.com/connect/oauth2/authorize?appid=$this->appId&redirect_uri=$redirect&response_type=code&scope=$scope&state=$state#wechat_redirect";
        #授权跳转
        redirect($url);
    }

    /**
     * 用户授权登录
     * @Author   Sean       Yan
     * @DateTime 2018-08-09
     * @param    string     $value [description]
     * @return   [type]            [description]
     */
    public function userAuthorization() {
        #返回Token信息
        $accessToken = $this->getUserAccessToken($_GET['code']);
        $reverse     = $this->isAttention($accessToken['openid']);
        #获取跳转URL地址
        $url = urldecode($_GET['state']) . "/openid/" . $accessToken['openid'] . "/subscribe/" . $reverse['subscribe'];
        #授权跳转
        redirect($url);
        exit(1);
    }

    /**
     * 判断是否关注
     * @Author   Sean       Yan
     * @DateTime 2018-09-06
     * @param    string     $openid       [description]
     * @return   boolean                  [description]
     */
    public function isAttention($openid = '') {
        try {
            $access_token = $this->getAccessToken();
            #设置URL地址
            $url = "https://api.weixin.qq.com/cgi-bin/user/info?access_token=$access_token&openid=$openid&lang=zh_CN";
            #提交数据
            $res = to_array($this->httpGet($url));
            if (isset($res['subscribe'])) {
                return $res;
            } else {
                throw new Exception($res['errmsg'], $res['errcode']);
            }
        } catch (Exception $e) {
            debug::exception($e);
        }
    }

    /**
     * 微信登录[API]-system/wechat/login【直接调用】
     * @Author   Sean       Yan
     * @DateTime 2018-09-06
     * @param    string     $url      授权的URL地址
     * @param    string     $scope    授权形式
     * @param    string     $type     授权数据提交
     * @param    string     $callback 授权回调地址
     * @return   [type]               [description]
     */
    public function login($url = "", $scope = 'snsapi_base', $type = "get", $callback = "-1") {
        $state    = isset($_GET['url']) ? $_GET['url'] : urlencode($url);
        $scope    = isset($_GET['scope']) ? $_GET['scope'] : $scope;
        $type     = isset($_GET['type']) ? $_GET['type'] : $type;
        $callback = isset($_GET['callback']) ? urldecode($_GET['callback']) : $callback;
        #获取授权页面
        $redirect = urlencode(ROOT . '/' . md5('wechat') . "_wechat/type/" . $type . "/callback/" . $callback);
        #设置跳转URl地址
        $redirect = "https://open.weixin.qq.com/connect/oauth2/authorize?appid=$this->appId&redirect_uri=$redirect&response_type=code&scope=$scope&state=$state#wechat_redirect";
        redirect($redirect);
    }

    /**
     * 微信登录[API]-代理快捷接口【直接调用】
     * @Author   Sean       Yan
     * @DateTime 2018-09-06
     * @param    string     $url      授权的URL地址
     * @param    string     $scope    授权形式
     * @param    string     $type     授权数据提交
     * @param    string     $callback 授权回调地址
     * @return   [type]               [description]
     */
    public function agency($url = "", $scope = 'snsapi_base', $type = "get", $callback = "-1") {
        $agency = C("wechat", "agency");
        try {
            if (empty($agency)) {
                throw new Exception("代理地址不能为空", 10003);
            }
            $url      = urlencode($url);
            $callback = urlencode($callback);
            $url      = trim($agency, "/") . "/system/wechat/login/url/$url/scope/$scope/type/$type/callback/$callback";
            redirect($url);
        } catch (Exception $e) {
            debug::exception($e);
        }
    }

    /**
     * 微信回调
     * @Author   Sean       Yan
     * @DateTime 2018-09-06
     * @param    string     $value [description]
     * @return   function          [description]
     */
    public function callback($value = '') {
        # code...
    }

    /**
     * @Author   Sean       Yan
     * @DateTime 2018-08-09
     * @param    string     $value [description]
     * @return   [type]            [description]
     */
    public function getUserAccessToken($code = '') {
        $key  = md5(__FILE__ . 'useraccess_token');
        $data = to_array(cache::get($key));
        if (!cache::check($key) || $data['expire_time'] < time()) {
            #提交URL地址
            $url = "https://api.weixin.qq.com/sns/oauth2/access_token?appid=$this->appId&secret=$this->appSecret&code=$code&grant_type=authorization_code";
            $res = to_array($this->httpGet($url));
            #返回Token信息
            $return = array('access_token' => $res['access_token'], 'openid' => $res['openid']);
            if ($return) {
                $return['expire_time'] = time() + 7000;
                cache::set($key, to_json($return));
            }
        } else {
            $return = array('access_token' => $data['access_token'], 'openid' => $data['openid']);
        }
        return $return;
    }

    /**
     * 获取JS的ticket
     * @Author   Sean       Yan
     * @DateTime 2018-08-09
     * @return   [type]     [description]
     * 如果是企业号用以下 URL 获取 ticket
     * api.weixin.qq.com/cgi-bin/ticket/getticket?type=jsapi&access_token=$accessToken
     */
    private function getJsApiTicket() {
        $key  = md5(__FILE__ . 'jsapi_ticket');
        $data = to_array(cache::get($key));
        if (!cache::check($key) || $data['expire_time'] < time()) {
            $accessToken = $this->getAccessToken();
            #提交URL地址
            $url  = "https://api.weixin.qq.com/cgi-bin/ticket/getticket?type=jsapi&access_token=$accessToken";
            $res  = to_array($this->httpGet($url));
            $data = array();
            #返回Ticket信息
            $ticket = $res['ticket'];
            if ($ticket) {
                $data['expire_time']  = time() + 7000;
                $data['jsapi_ticket'] = $ticket;
                cache::set($key, to_json($data), 7000);
            }
        } else {
            $ticket = $data['jsapi_ticket'];
        }
        return $ticket;
    }

    /**
     * 获取Token
     * @Author   Sean       Yan
     * @DateTime 2018-08-09
     * @return   [type]     [description]
     * 如果是企业号用以下URL获取access_token
     * qyapi.weixin.qq.com/cgi-bin/gettoken?corpid=$this->appId&corpsecret=$this->appSecret;
     */
    private function getAccessToken() {
        $key  = md5(__FILE__ . 'access_token');
        $data = to_array(cache::get($key));
        if (!cache::check($key) || $data['expire_time'] < time()) {
            #提交URL地址
            $url  = "https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid=$this->appId&secret=$this->appSecret";
            $res  = to_array($this->httpGet($url));
            $data = array();
            #返回Token信息
            $access_token = $res['access_token'];
            if ($access_token) {
                $data['expire_time']  = time() + 7000;
                $data['access_token'] = $access_token;
                cache::set($key, to_json($data), 7000);
            }
        } else {
            $access_token = $data['access_token'];
        }
        return $access_token;
    }
    /**
     * 获取URL请求
     * @Author   Sean       Yan
     * @DateTime 2018-09-07
     * @param    [type]     $url [description]
     * @return   [type]          [description]
     */
    private function httpGet($url) {
        $curl = curl_init();
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_TIMEOUT, 500);
        #为保证第三方服务器与微信服务器之间数据传输的安全性，所有微信接口采用https方式调用，必须使用下面2行代码打开ssl安全校验。
        #如果在部署过程中代码在此处验证失败，请到 http://curl.haxx.se/ca/cacert.pem 下载新的证书判别文件。
        curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, 2);
        curl_setopt($curl, CURLOPT_URL, $url);

        $res = curl_exec($curl);
        curl_close($curl);

        return $res;
    }

    /**
     * 获取URL请求
     * @Author   Sean       Yan
     * @DateTime 2018-09-07
     * @param    [type]     $url [description]
     * @return   [type]          [description]
     */
    private function httpPost($url, $data) {
        $curl     = curl_init();
        $header[] = "Content-Type:application/json;charset=utf-8";
        if (!empty($header)) {
            curl_setopt($curl, CURLOPT_HTTPHEADER, $header); //设置 HTTP 头字段的数组。格式： array('Content-type: text/plain', 'Content-length: 100')
        }
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_TIMEOUT, 500);
        curl_setopt($curl, CURLOPT_HEADER, false);
        curl_setopt($curl, CURLOPT_CUSTOMREQUEST, "POST");
        curl_setopt($curl, CURLOPT_POSTFIELDS, json_encode($data, 320));
        #为保证第三方服务器与微信服务器之间数据传输的安全性，所有微信接口采用https方式调用，必须使用下面2行代码打开ssl安全校验。
        #如果在部署过程中代码在此处验证失败，请到 http://curl.haxx.se/ca/cacert.pem 下载新的证书判别文件。
        curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, 2);
        curl_setopt($curl, CURLOPT_URL, $url);
        $res = curl_exec($curl);
        curl_close($curl);
        return $res;
    }
    /********************************************************************************************************************
     ********************************************************************************************************************
     *****************************************************【第三方库】*****************************************************
     ********************************************************************************************************************
     ********************************************************************************************************************/
    /**
     * 第三方发送消息给公众平台
     * @Author   Sean       Yan
     * @DateTime 2018-09-07
     * @return   [type]     [description]
     */
    public function thirdPartiesMessages() {
        $encodingAesKey = C("wechat", "encodingAesKey");
        $token          = C("wechat", "token");
        $appId          = C("wechat", "componentAppid");
        $pc             = new WXBizMsgCrypt($token, $encodingAesKey, $appId);
        $format         = file_get_contents('php://input');
        #第三方收到公众号平台发送的消息
        $msg     = "";
        $errCode = $pc->decryptMsg($_GET['msg_signature'], $_GET['timestamp'], $_GET['nonce'], $format, $msg);
        if ($errCode == 0) {
            cache::set("ComponentVerifyTicket", $msg);
            echo "success";
        } else {
            echo $errCode;
        }
        exit();
    }

    /**
     * 获取ComponentVerifyTicket
     * @Author   Sean       Yan
     * @DateTime 2018-09-07
     * @param    string     $value [description]
     */
    public function getComponentVerifyTicket() {
        $msg = cache::get("ComponentVerifyTicket");
        $xml = new \DOMDocument();
        $xml->loadXML($msg);
        $ComponentVerifyTicket = $xml->getElementsByTagName('ComponentVerifyTicket')->item(0)->nodeValue;
        if ($ComponentVerifyTicket) {
            return $ComponentVerifyTicket;
        } else {
            return false;
        }
    }

    /**
     * 获取第三方Token
     * @Author   Sean       Yan
     * @DateTime 2018-09-07
     * @return   [type]     [description]
     */
    public function componentAccessToken() {
        $key  = md5(__FILE__ . 'component_access_token');
        $data = to_array(cache::get($key));
        if (!cache::check($key) || $data['expire_time'] < time()) {
            #提交URL地址
            $url  = "https://api.weixin.qq.com/cgi-bin/component/api_component_token";
            $data = array(
                "component_appid"         => C("wechat", "componentAppid"),
                "component_appsecret"     => C("wechat", "componentSecret"),
                "component_verify_ticket" => $this->getComponentVerifyTicket(),
            );
            $res = to_array($this->httpPost($url, $data));
            #返回Token信息
            $access_token = $res['component_access_token'];
            if ($access_token) {
                $data['expire_time']            = time() + 7000;
                $data['component_access_token'] = $access_token;
                cache::set($key, to_json($data), 7000);
            }
        } else {
            $access_token = $data['component_access_token'];
        }
        return $access_token;
    }

    /**
     * @Author   Sean       Yan
     * @DateTime 2018-09-07
     * @return   [type]            [description]
     */
    public function getPreAuthCode() {
        $key  = md5(__FILE__ . 'pre_auth_code');
        $data = to_array(cache::get($key));
        if (!cache::check($key) || $data['expire_time'] < time()) {
            $component_access_token = $this->componentAccessToken();
            #提交URL地址
            $url  = "https://api.weixin.qq.com/cgi-bin/component/api_create_preauthcode?component_access_token=$component_access_token";
            $data = array(
                "component_appid" => C("wechat", "componentAppid"),
            );
            $res = to_array($this->httpPost($url, $data));
            #返回Token信息
            $access_token = $res['pre_auth_code'];
            if ($access_token) {
                $data['expire_time']   = time() + 500;
                $data['pre_auth_code'] = $access_token;
                cache::set($key, to_json($data), 7000);
            }
        } else {
            $access_token = $data['pre_auth_code'];
        }
        return $access_token;
    }

    /**
     * 绑定授权接口-【直接调用】
     * @Author   Sean       Yan
     * @DateTime 2018-09-07
     * @param    string     $value [description]
     * @return   [type]            [description]
     */
    public function bindcomponent() {
        $url             = isset($_GET['url']) ? $_GET['url'] : '-1';
        $uid             = isset($_GET['uid']) ? $_GET['uid'] : '-1';
        $component_appid = C("wechat", "componentAppid");
        $pre_auth_code   = $this->getPreAuthCode();
        $redirect_uri    = urlencode(ROOT . '/' . md5('Wechat authorization callback') . "_wechat/url/" . $url . '/uid/' . $uid);
        $auth_type       = 3;
        $url             = "https://mp.weixin.qq.com/safe/bindcomponent?action=bindcomponent&auth_type=3&no_scan=1&component_appid=$component_appid&pre_auth_code=$pre_auth_code&redirect_uri=$redirect_uri&auth_type=$auth_type#wechat_redirect";
        $this7qrcode     = qrcode::base64($url);
        require dirname(dirname(__FILE__)) . "/bin/authorization.php";
        exit();
    }

    /**
     * 第三方授权回调地址
     * [FunctionName description]
     * @param string $value [description]
     */
    public function thirdAuthorizeCallback($code = '') {
        $component_access_token = $this->componentAccessToken();
        $data                   = array(
            "component_appid"    => C("wechat", "componentAppid"),
            "authorization_code" => $code['auth_code'],
        );
        #提交URL地址
        $url = "https://api.weixin.qq.com/cgi-bin/component/api_query_auth?component_access_token=$component_access_token";
        $res = to_array($this->httpPost($url, $data));
        if (isset($res['authorization_info'])) {
            $data = $res['authorization_info'];
            #设置存储信息
            $key = md5($code['uid'] . md5($code['uid'] . 'thirdAuthorizeCallback') . "_wechat");
            #设置缓存时间
            $data['expire_time'] = time() + 7000;
            F($key, to_json($data));
            if ($code['url'] != "-1") {
                $file = dirname(dirname(__FILE__)) . "/bin/successful.html";
                echo file_get_contents($file);
            } else {
                redirect($code['url']);
            }
        } else {
            echo "授权失败";
        }
        exit();
    }

    /**
     * 获取第三方授权Token
     * @Author   Sean       Yan
     * @DateTime 2018-08-09
     * @return   [type]     [description]
     * 如果是企业号用以下URL获取access_token
     * qyapi.weixin.qq.com/cgi-bin/gettoken?corpid=$this->appId&corpsecret=$this->appSecret;
     */
    private function getAuthorizerAccessToken($uid) {
        $access_token = false;
        #获取数据信息
        $info = $this->getUidAppid($uid);
        if ($info && $info['expire_time'] < time()) {
            $component_access_token = $this->componentAccessToken();
            #提交URL地址
            $url  = "https://api.weixin.qq.com/cgi-bin/component/api_authorizer_token?component_access_token=$component_access_token";
            $res  = to_array($this->httpGet($url));
            $data = array(
                "component_appid"          => C("wechat", "componentAppid"),
                "authorizer_appid"         => $info['authorizer_appid'],
                "authorizer_refresh_token" => $info['authorizer_refresh_token'],
            );
            #返回Token信息
            $access_token = $res['authorizer_access_token'];
            if ($access_token) {
                $info['expire_time']              = time() + 7000;
                $info['authorizer_access_token']  = $access_token;
                $info['authorizer_refresh_token'] = $res['authorizer_refresh_token'];
                F($key, to_json($info));
            }
        } else {
            $access_token = $data['authorizer_access_token'];
        }
        return $access_token;
    }

    /**
     * 获取对应UID的APPid或授权信息
     * @Author   Sean       Yan
     * @DateTime 2018-09-11
     * @param    string     $uid  [description]
     * @param    string     $type [description]
     * @return   [type]           [description]
     */
    public function getUidAppid($uid = '', $type = "all") {
        $key  = md5($uid . md5($uid . 'thirdAuthorizeCallback') . "_wechat");
        $data = to_array(F($key, '[get]'));
        if ($data) {
            switch ($type) {
            case 'appid':
                return $data['authorizer_appid'];
                break;
            default:
                return $data;
                break;
            }
        } else {
            return false;
        }
    }

    /**
     * 第三方授权信息-小程序相同
     * @Author   Sean       Yan
     * @DateTime 2018-09-12
     * @return   [type]            [description]
     */
    public function thirdAccountInformation($uid = '') {
        $component_access_token = $this->componentAccessToken();
        #提交数据
        $data = array(
            "component_appid"  => C("wechat", "componentAppid"),
            "authorizer_appid" => $this->getUidAppid($uid, "appid"),
        );
        #提交的URL地址
        $url = "https://api.weixin.qq.com/cgi-bin/component/api_get_authorizer_info?component_access_token=$component_access_token";
        $res = to_array($this->httpPost($url, $data));
        if ($res && isset($res['authorizer_info'])) {
            return $res;
        } else {
            return false;
        }
    }

    /**
     * 第三发消息微信回调
     * @Author   Sean       Yan
     * @DateTime 2018-09-06
     * @param    string     $value [description]
     * @return   function          [description]
     */
    public function thirdCallback($code) {
        P($code);
        $encodingAesKey = C("wechat", "encodingAesKey");
        $token          = C("wechat", "token");
        $appId          = C("wechat", "componentAppid");
        $pc             = new WXBizMsgCrypt($token, $encodingAesKey, $appId);
        $format         = file_get_contents('php://input');
        #第三方收到公众号平台发送的消息
        $msg     = "";
        $errCode = $pc->decryptMsg($code['msg_signature'], $code['timestamp'], $code['nonce'], $format, $msg);
        if ($errCode == 0) {
            echo $msg;
        } else {
            echo $errCode;
        }
        exit();
    }

    /**
     * 第三方消息加密
     * @Author   Sean       Yan
     * @DateTime 2018-09-12
     * @param    string     $value [description]
     * @return   [type]            [description]
     */
    public function thirdMessageEncryption($appId = '') {
        # code...
    }
}