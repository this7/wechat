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
    public function userAuthorization($value = '') {
        #返回Token信息
        $accessToken = $this->getUserAccessToken($_GET['code']);
        #获取跳转URL地址
        $url = urldecode($_GET['state']) . "/access_token/" . $accessToken['access_token'] . "/openid/" . $accessToken['openid'];
        #授权跳转
        redirect($url);
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
                cache::set($key, to_json($data));
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
            P($res);
            #返回Token信息
            $access_token = $res['access_token'];
            if ($access_token) {
                $data['expire_time']  = time() + 7000;
                $data['access_token'] = $access_token;
                cache::set($key, to_json($data));
            }
        } else {
            $access_token = $data['access_token'];
        }
        return $access_token;
    }

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

    private function get_php_file($filename) {
        return trim(substr(file_get_contents($filename), 15));
    }
    private function set_php_file($filename, $content) {
        $fp = fopen($filename, "w");
        fwrite($fp, "<?php exit();?>" . $content);
        fclose($fp);
    }

}