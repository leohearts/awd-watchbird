<?php
/*

A Simple PHP WAF for AWD


 /$$      /$$  /$$$$$$  /$$$$$$$$ /$$$$$$  /$$   /$$ /$$$$$$$  /$$$$$$ /$$$$$$$  /$$$$$$$ 
| $$  /$ | $$ /$$__  $$|__  $$__//$$__  $$| $$  | $$| $$__  $$|_  $$_/| $$__  $$| $$__  $$
| $$ /$$$| $$| $$  \ $$   | $$  | $$  \__/| $$  | $$| $$  \ $$  | $$  | $$  \ $$| $$  \ $$
| $$/$$ $$ $$| $$$$$$$$   | $$  | $$      | $$$$$$$$| $$$$$$$   | $$  | $$$$$$$/| $$  | $$
| $$$$_  $$$$| $$__  $$   | $$  | $$      | $$__  $$| $$__  $$  | $$  | $$__  $$| $$  | $$
| $$$/ \  $$$| $$  | $$   | $$  | $$    $$| $$  | $$| $$  \ $$  | $$  | $$  \ $$| $$  | $$
| $$/   \  $$| $$  | $$   | $$  |  $$$$$$/| $$  | $$| $$$$$$$/ /$$$$$$| $$  | $$| $$$$$$$/
|__/     \__/|__/  |__/   |__/   \______/ |__/  |__/|_______/ |______/|__/  |__/|_______/                                                         
                                                                                    

Credits:
	[AWD_PHP watchbird] (Original WAF Framework)
	[Longlone](https://github.com/WAY29) (Main developer)
	[Leohearts](https://leohearts.com) (Main developer)
	[guoqing](https://blog.izgq.net/archives/1029/) (Function: getFormData(), Regenerating RAW multipart/form-data post data), 已联系授权

Lisence:
	GNU AGPLv3 (GNU Affero General Public License v3.0)
	https://choosealicense.com/licenses/agpl-3.0/

		Permissions			Conditions							Limitations

		Commercial use		Disclose source						Liability
		Distribution		License and copyright notice		Warranty
		Modification		Network use is distribution
		Patent use			Same license
		Private use			State changes

	Attribution-NonCommercial-ShareAlike 4.0 International （CC BY-NC-SA 4.0）	(For Function: getFormData() Only)
	https://creativecommons.org/licenses/by-nc-sa/4.0/

		You are free to:
		Share — copy and redistribute the material in any medium or format
		Adapt — remix, transform, and build upon the material
		Under the following terms:
		Attribution — You must give appropriate credit, provide a link to the license, and indicate if changes were made. You may do so in any reasonable manner, but not in any way that suggests the licensor endorses you or your use.

		NonCommercial — You may not use the material for commercial purposes.

		ShareAlike — If you remix, transform, or build upon the material, you must distribute your contributions under the same license as the original.

		No additional restrictions — You may not apply legal terms or technological measures that legally restrict others from doing anything the license permits.
	
*/


$config_path = '/tmp/watchbird/watchbird.conf';
$check_upload_path = "/tmp/wb_check_upload";
// $level = 4;  // 0~4 等级越高,防护能力越强,默认为4
error_reporting(0);
ob_end_clean();

function is_browser($v,$vv){
    return strstr($v, $vv);
}



function get_fake_flag(){
	global $config;
	$flag = trim(file_get_contents($config->flag_path));
	$str="QWERTYUIOPASDFGHJKLZXCVBNM1234567890qwertyuiopasdfghjklzxcvbnm";
	str_shuffle($str);
	$fake_flag='flag{'.substr(str_shuffle($str),0,strlen($flag)-6).'}';
	return $fake_flag;
}

function get_preg_flag(){  // 获取自己flag的正则表达式并保存在文件里
	global $config;
	$result = '';
	$flag = file_get_contents($config->flag_path);
	$flag = trim($flag);
	if ($flag === ""){
		return 'flag{sauhiudsahiudhasiuhduihwauidhwsuisdhaiuhduiahuiduishudiahusdhauwshdushuidaud|';
	}
	if(strlen($flag) >= 18)
	{
		$flag1 = substr($flag, 0, strlen($flag)/3);
		$flag1 = preg_quote($flag1, '/');
		$result .= $flag1.'*|';
		$flag2 = substr($flag, strlen($flag)/3, strlen($flag)*2/3);
		$flag2 = preg_quote($flag2, '/');
		$result .= $flag2.'*|';
		$flag3 = substr($flag, strlen($flag)*2/3);
		$flag3 = preg_quote($flag3, '/');
		$result .= $flag3.'*|';
	}else{
		$result = 'flag{|'.preg_quote($flag).'|';
	}
	// echo $result;
	return $result;
}


class configmanager
{
	// 功能开启选项
	public $flag_path = '/flag';  // 自己flag所在的路径
	public $LDPRELOAD_PATH = '/var/www/html/waf.so';    //共享库路径
	public $password_sha1 = 'unset';
	public $open_basedir = '/';
	// public $level = 4;  // 0~4 等级越高,防护能力越强,默认为4

	// level处理
	public $waf_headers = 1;  // headers防御
	public $waf_ddos = 1;  // ddos防御
	public $waf_upload = 1;  // 上传防御
	public $waf_special_char = 0; // 特殊字符防御
	public $waf_sql = 1;  // sql防御
	public $waf_rce = 1;  // rce防御
	public $waf_ldpreload = 1;    //基于LD_PRELOAD的rce防护
	public $waf_lfi = 1;  // LFI/LFR 防御
	public $waf_unserialize = 1; // phar反序列化防御
	public $waf_flag = 1;  // getflag防御
	public $response_content_match = 1; // 匹配响应中有无flag特征
	public $debug = 0;  // debug模式
	public $scheduled_killall = 0;
	public $allow_ddos_time = 5;  // 每秒最多5个访问 

	public $waf_fake_flag = "flag{Longlone:W0r1<_HaRd3r}";  // 虚假flag,需开启waf_flag
	public $remote_ip = "127.0.0.1";    //	服务器ip
	public $remote_port = 80;    //	服务器端口

	public $max_log_size = 40000;	//单个日志文件最大大小

	//名单配置
	public $upload_whitelist = "/jpg|png|gif|txt/i";  // upload白名单
	public $sql_blacklist = "/drop |dumpfile\b|INTO FILE|union select|outfile\b|load_file\b|multipoint\(/i";
	public $rce_blacklist = "/`|var_dump|str_rot13|serialize|base64_encode|base64_decode|strrev|eval\(|assert|file_put_contents|fwrite|curl_exec\(|dl\(|readlink|popepassthru|preg_replace|create_function|array_map|call_user_func|array_filter|usort|stream_socket_server|pcntl_exec|passthru|exec\(|system\(|chroot\(|scandir\(|chgrp\(|chown|shell_exec|proc_open|proc_get_status|popen\(|ini_alter|ini_restore|ini_set|LD_PRELOAD|ini_alter|ini_restore|ini_set|base64 -d/i";
	function change($key, $val)
	{
		global $config_path;
		$this->$key = $val;
		echo $key;
		echo $val . "\n";
		if (is_numeric($val)) {
			$this->$key = intval($val);
		}
		file_put_contents($config_path, serialize($this));
		die('succ');
	}
}

class watchbird{
	private $request_url;
	private $request_method;
	private $request_data;
	private $headers;
	private $raw;
	private $dir;
	private $logdir;
	private $uploaddir;
	private $tokendir;
	private $allow_time;
	private $response_content;
	private $timestamp;
	/*
	watchbird类
	*/

// 自动部署构造方法
function __construct(){
	//echo $_SERVER['SERVER_PORT']."\n";
	global $config, $content_disallow, $waf_fake_flag2;
	$this->dir = '/tmp/watchbird/';
	$this->logdir = $this->dir.'log/';
	$this->uploaddir = $this->dir.'upload/';
	$this->ipdir = $this->dir.'ip/';
	$this->tokendir = $this->dir . 'token/';
	if ($config->waf_ldpreload == 1) {
		putenv("LD_PRELOAD=" . $config->LDPRELOAD_PATH);
	}
	$this->headers = getallheaders(); //获取header  
	foreach ($this->headers as $key => $val){
		if ($val == ""){
			unset($this->headers[$key]);
		}
	}
	$this->timestamp = getMillisecond();
	if ($config->open_basedir !== '/') {
		ini_set("open_basedir", $config->open_basedir . ':/tmp/');
	}
	if(isset($_SERVER['HTTP_WATCHBIRDTOKEN']) && file_exists($this->tokendir . $_SERVER['HTTP_WATCHBIRDTOKEN'])){
		unlink($this->tokendir . $_SERVER['HTTP_WATCHBIRDTOKEN']);
		putenv("php_timestamp=".$_SERVER['HTTP_WATCHBIRDTIMESTAMP']);
		return 0;
	}
	else{
		putenv("php_timestamp=" . $this->timestamp);	// 用于ld_preload rce防护记录日志
	}
	$this->allow_time = $config->allow_ddos_time;  // 获取每秒最大访问次数
	if ($config->waf_ddos == true){
		$this->watch_ddos();
	}
	$this->e_mkdir($this->dir);
	$this->e_mkdir($this->logdir);
	$this->e_mkdir($this->uploaddir);
	$this->e_mkdir($this->ipdir);
	$this->e_mkdir($this->tokendir);
	$this->request_url = $this->filter_0x25(urldecode($_SERVER['REQUEST_URI'])); //	获取url来进行检测
	$this->request_data = file_get_contents('php://input');	//	获取post
	if ($config->waf_headers == true)
	{   
		$this->watch_headers();  // 监测headers
	}
	$this->write_access_log_probably();  //	记录访问纪录, 类似于日志
	$this->write_access_logs_detailed();  //	记录详细访问请求包  
	if ($config->waf_upload==true) {
		$this->watch_upload();  // 记录上传纪录
	}
	if($_SERVER['REQUEST_METHOD'] != 'POST' && $_SERVER['REQUEST_METHOD'] != 'GET'){
		$method = $_SERVER['REQUEST_METHOD'];
		$this->write_attack_log("Catch attack: Suspicious method [ ".$method."] ");
	}
	foreach ($_GET as $keywords){   //	监测GET参数，出现问题则记录
		$this->watch_attack_keyword($this->watch_special_char($keywords)); 
	}
	if  ($this->request_data != '')
	{
		foreach ($_POST as $keywords){   //	监测POST参数，出现问题则记录
			$this->watch_attack_keyword($this->watch_special_char($keywords)); 
		}
	}
	if ($config->response_content_match){   //	深度检测响应包
		ob_end_clean();	// 处理BOM头
		$this->getcont();  // 开始自检
		if (preg_match($content_disallow, $this->response_content)!==0){
				$this->write_flag_log();
				die($waf_fake_flag2);
		}
		else {
			$co=explode("\r\n\r\n",$this->response_content,2)[1];
			$raw_header=explode("\r\n\r\n",$this->response_content,2)[0];
			$res_header = explode("\r\n",explode("\r\n",$raw_header,2)[1]);
			foreach ($res_header as $leo1){
				if (stripos($leo1, 'transfer-encoding') !== false) {continue;}
				header($leo1,true);
			}
			// header("Content-Encoding: identity", true);
			// while (preg_match("/^[0-9,a-z]{5}/", $co)) {
			// 	$co = substr($co, 5);
			// }
			// while (preg_match("/^[0-9,a-z]{4}/",$co)){
			// 	$co=substr($co,4);
			// }
			
			// $co=substr($co,strpos($co,pack("CCC",0xef,0xbb,0xbf)));  // 处理BOM头
			// if (substr($co,0,3) == pack("CCC",0xef,0xbb,0xbf)){
			// 	$co=substr($co,3);
			// }
			if (substr($co,-7)=="\r\n0\r\n\r\n" && preg_match("/^[0-9, a-f]/", $co)){
				// $co=rtrim($co,"\r\n0\r\n\r\n");
				// $co .= "\r\n\r\n";
				// header("Transfer-Encoding: chunked", true);	// finally!
				$co = decode_chunked($co);
			}
			die($co);  // 将内容返回给用户
		}
	}
}

/*
判断文件夹是否存在并创建文件夹
*/
function e_mkdir($folder){
	if (is_dir($folder) == false)
	{
		mkdir($folder, 0777, true);
		return true;
	}	
	return false;
}

/*
删除文件夹下所有文件
*/
function deldir($dir) {
	$dh=opendir($dir);
	while ($file=readdir($dh)) {
		if($file!="." && $file!="..") {
			$fullpath=$dir."/".$file;
			if(!is_dir($fullpath)) {
				unlink($fullpath);
			} 
			else {
				$this->deldir($fullpath);
			}
		}
	}
}


/*
die并且输出logo
*/
function logo(){
	global $config;
	$logo = <<<LOGO
	__        ___  _____ ____ _   _ ____ ___ ____  ____
	\ \      / / \|_   _/ ___| | | | __ )_ _|  _ \|  _ \
	 \ \ /\ / / _ \ | || |   | |_| |  _ \| || |_) | | | |
	  \ V  V / ___ \| || |___|  _  | |_) | ||  _ <| |_| |
	   \_/\_/_/   \_\_| \____|_| |_|____/___|_| \_\____/

LOGO;
$UAs=array("MSIE", "Firefox", "Chrome", "Safari", "Opera");
$UA=$_SERVER["HTTP_USER_AGENT"];
if (count(array_filter(array_map("is_browser", array_fill(0, count($UAs), $UA), $UAs)))){
$logo="<pre>\n".$logo."\n</pre>";
$logo=str_replace("\r","", $logo);
$logo=str_replace("\n","</br>", $logo);
}
echo $logo;
if ($config->debug){
	echo debug_backtrace()[1]['function'];
}
die();
}


/*
DDOS防御
*/
function watch_ddos(){
	$IP = $_SERVER['REMOTE_ADDR'];
	$IP = str_replace(":", '_', $IP);
	$date = date('H_i_s');
	$IP_dir = $this->ipdir . '/' . $IP . '/';
	$this->e_mkdir($IP_dir);
	$IP_date_file = $IP_dir . $date . '_log.txt';
	if (is_file($IP_date_file))
	{
		$time = intval(file_get_contents($IP_date_file));
		$time += 1;
		if ($time > $this->allow_time)
		{
			$this->logo();
		}
		else{
			file_put_contents($IP_date_file, $time, LOCK_EX);
		}
	}
	else{
		$this->deldir($IP_dir);
		file_put_contents($IP_date_file, 1, LOCK_EX);
	}
}   

/*
监测headers
*/
function watch_headers(){
	global $config;
	foreach($this->headers as $k=>$v) {
		if (preg_match($config->sql_blacklist, urldecode($v)) || preg_match($config->rce_blacklist, urldecode($v))) {
			$this->headers[$k] = '';
			// $URI = explode('?',$this->request_url);
			// header('Location: http://'.$_SERVER['SERVER_NAME'].':'.$_SERVER["SERVER_PORT"].$URI[0]);
			$this->logo();
		}
	}
}


/*
监测不可见字符造成的截断和绕过效果，注意网站请求带中文需要简单修改
*/
function watch_special_char($str){
	global $config;
	$txt = '';
	for($i=0;$i<strlen($str);$i++){
		$ascii = ord($str[$i]);
		if($ascii>126 || $ascii < 32){ //	有中文这里要修改
			if(!in_array($ascii, array(9,10,13))){
				$txt .= "Interrupt";
			}else{
				$txt .= "  Catch attack: Suspected attack character < ".$str[$i]. " > ";
			}
			break;
		}
		if (preg_match("/\||\`|\;|\,|\'|\"|<|>/", $str[$i]))
		{
			$txt .= "  Catch attack: Suspected attack character < ".$str[$i]." > ";
			break;
		}
	}
	if ($txt != '')
	{
		if($config->waf_special_char == true){
			$this->write_attack_log($txt);
			$this->logo();
		}
	}
	return $str;
}
/*
监测文件上传
*/
function watch_upload(){
	global $config, $check_upload_path;
	foreach ($_FILES as $key => $value) {
		if($_FILES[$key]['error'] == 0){
			$ext = substr(strrchr($_FILES[$key]["name"], '.'), 1);
			$this->write_attack_log("Catch attack: < Evil Upload, please check ".$this->uploaddir." dir > ");
			copy($_FILES[$key]["tmp_name"], $this->uploaddir.date("d_H_i_s").'.'.$ext.'.txt');
			file_put_contents($check_upload_path,"check!");
			if(!preg_match($config->upload_whitelist, $ext))
			{
				unlink($_FILES[$key]['tmp_name']);
				echo 'Upload success! Check upload/'.substr(md5($_FILES[$key]["name"]), 0, rand(10, 30)).'.'.$ext;
				die();
			}
		}
		$new_file_content = file_get_contents($_FILES[$key]['tmp_name']);
		if (preg_match("/<?php/i", $new_file_content) === 1){
			$this->write_attack_log("Catch attack: < Evil Upload, please check " . $this->uploaddir . " dir > ");
			copy($_FILES[$key]["tmp_name"], $this->uploaddir . date("d_H_i_s") . '.' . $ext . '.txt');
			unlink($_FILES[$key]['tmp_name']);
				echo 'Upload success. Check upload/' . substr(md5($_FILES[$key]["name"]), 0, rand(10, 30)) . '.' . $ext;
			die();
		}
	}
}

/*
监测网站程序存在二次编码绕过漏洞造成的%25绕过，此处是循环将%25替换成%，直至不存在%25
*/
function filter_0x25($str){
	if(strpos($str,"%25") !== false){
		$str = str_replace("%25", "%", $str);
		return $this->filter_0x25($str);
	}else{
		return $str;
	}
}

/*
对非法请求进行重定向
*/
// function redirect(){
// 	$URI = explode('?',$this->request_url);
// 	header('Location: http://'.$_SERVER['SERVER_NAME'].':'.$_SERVER["SERVER_PORT"].$URI[0]);
// 	die();
// }

/*
监测攻击关键字
*/
function watch_attack_keyword($str){
	global $config;
	if(preg_match($config->sql_blacklist, $str)){
		if($config->waf_sql == true){
			$this->write_attack_log("Catch attack: < SQLI > ");
			$this->logo();
		}
	}
	if(substr_count($str,$_SERVER['PHP_SELF']) < 2){
		$tmp = str_replace($_SERVER['PHP_SELF'], "", $str);
		if(preg_match("/\.\.|.*\.php[2357]{0,1}|\.phtml/i", $tmp)){ 
			if($config->waf_lfi == true){
				$this->write_attack_log("Catch attack: < LFI/LFR > ");
				$this->logo();
			}
		}
	}else{
		if($config->waf_lfi == true){
			$this->write_attack_log("Catch attack: < LFI/LFR > ");
			$this->logo();
		}
	}
	if(preg_match($config->rce_blacklist, $str)){
		if($config->waf_rce == true){
			$this->write_attack_log("Catch attack: < RCE > ");
			$this->logo();
		}
	}
	if(preg_match("/phar|zip|compress.bzip2|compress.zlib/i", $str)){
		if($config->waf_unserialize == true){
			$this->write_attack_log("Catch attack: < phar unserialize >");
			$this->logo();
		}
	}
	if(preg_match("/flag/i", $str)){
		if($config->waf_flag == true){
			$this->write_attack_log("Catch attack: < !!GETFLAG!! >");
			die($config->waf_fake_flag);
		}
	}
}


//	记录每次大概访问记录，类似日志，以便在详细记录中查找
function write_access_log_probably() { 
	global $config;
	$tmp = sha1("Syclover").$this->timestamp.sha1("Syclover");
	$tmp .= "[" . date('H:i:s') . "]" . $_SERVER['REQUEST_METHOD'].' '.$_SERVER['REQUEST_URI'].' '.$_SERVER['SERVER_PROTOCOL'];
	if (!empty($this->request_data)){
		$tmp .= "\n".$this->request_data; 
	}
	$tmp .= "\n";
	file_put_contents($this->logdir.'all_requests'.'.txt', $tmp, FILE_APPEND | LOCK_EX);
	if (filesize($this->logdir . 'all_requests' . '.txt') > $config->max_log_size) {
		unlink($this->logdir . 'all_requests' . '.txt');
	}
}

//	记录详细的访问头记录，包括GET POST http头, 以获取waf未检测到的攻击payload
function write_access_logs_detailed(){
	global $config;
	$tmp = sha1("Syclover"). $this->timestamp. sha1("Syclover");
	$tmp .= "[" . date('H:i:s') . "]\n";
	$tmp .= "SRC IP: " . $_SERVER["REMOTE_ADDR"]."\n";
	$tmp .= $_SERVER['REQUEST_METHOD'].' '.$_SERVER['REQUEST_URI'].' '.$_SERVER['SERVER_PROTOCOL']."\n"; 
	foreach($this->headers as $k => $v) {
		if ($k==="isself"){
			continue;
		}
		$tmp .= $k . ': ' . $v . "\n";
	}
	if (!empty($this->request_data)) {
		$tmp .= "\n". $this->request_data . "\n";
	}
	$tmp .= "\n";
	file_put_contents($this->logdir.'web_log'.'.txt', $tmp, FILE_APPEND | LOCK_EX);
	if (filesize($this->logdir . 'web_log' . '.txt') > $config->max_log_size) {
		unlink($this->logdir . 'web_log' . '.txt');
	}
}
	
/*
记录攻击payload 第一个参数为记录类型  使用时直接调用函数
*/
function write_attack_log($alert){
	global $config;
	$tmp = sha1("Syclover").$this->timestamp. sha1("Syclover");
	$tmp .= "[" . date('H:i:s') . "] {".$alert."}\n";
	$tmp .= "SRC IP: " . $_SERVER["REMOTE_ADDR"]."\n";
	$tmp .= $_SERVER['REQUEST_METHOD'].' '.$_SERVER['REQUEST_URI'].' '.$_SERVER['SERVER_PROTOCOL']."\n"; 
	foreach($this->headers as $k => $v) {
		if ($k==="isself"){
			continue;
		}
		$tmp .= $k . ': ' . $v . "\n";
	}
	if (!empty($this->request_data)) {
		$tmp .= "\n". $this->request_data . "\n";
	}
	file_put_contents($this->logdir.'under_attack_log.txt', $tmp, FILE_APPEND | LOCK_EX);
	if (filesize($this->logdir . 'under_attack_log' . '.txt') > $config->max_log_size) {
		unlink($this->logdir . 'under_attack_log' . '.txt');
	}
	if ($alert == 'Catch attack: < !!GETFLAG!! >')  // 顺便写入另外一个日志
	{
		file_put_contents($this->logdir.'flag_eye_to_eye.txt', $tmp, FILE_APPEND | LOCK_EX);
		if (filesize($this->logdir . 'flag_eye_to_eye' . '.txt') > $config->max_log_size) {
			unlink($this->logdir . 'flag_eye_to_eye' . '.txt');
		}
	}
}



/*
将流量发送到本地服务器进行自检
*/
function getcont(){
	global $config;
	$headerstr = "";
	$this->response_content = "";
	$this->headers['watchbirdtimestamp'] = $this->timestamp;
	$this->headers['Connection'] = "Close";
	$this->headers["Accept-Encoding"] = "identity";
	$token = rand();
	$this->headers['WatchbirdToken'] = $token;
	touch ($this->tokendir . $token);
	foreach($this->headers as $k => $v) {
		$headerstr .= $k . ': ' . $v . "\r\n";
	}
	$fp = fsockopen($config->remote_ip, $config->remote_port, $errno, $errstr, 30);
	if (!$fp) {
			echo "500 Internal Server Error.";
	}
	else {
		$out = $_SERVER['REQUEST_METHOD'].' '.$_SERVER['REQUEST_URI'].' '.$_SERVER['SERVER_PROTOCOL']."\r\n";
		$out .= $headerstr;
		$out .= "\r\n";
		$out .= $this->request_data . "\r\n";
		if ($this->request_data===''&&$_SERVER['REQUEST_METHOD']=="POST"){
			$out .= getFormData();
		}
		stream_set_timeout($fp, 5);
		fwrite($fp, $out);
		//echo $out;
		while (!feof($fp)) {
			$tmp3 = fgets($fp, 4);
			if ($tmp3 === false){
				break;
			}
			$this->response_content .= $tmp3;
		}
		fclose($fp);
		if ($config->debug){
			echo $out;
			echo $this->response_content;
		}
	}
}

/*
当响应包中存在flag时写入日志
*/
function write_flag_log(){
	global $config;
	$tmp = sha1("Syclover").$this->timestamp.sha1("Syclover");
	$tmp .= "[" . date('H:i:s') . "] \n";
	$tmp .= "\nRequest:\n";
	$tmp .= "SRC IP: " . $_SERVER["REMOTE_ADDR"]."\n";
	$tmp .= $_SERVER['REQUEST_METHOD'].' '.$_SERVER['REQUEST_URI'].' '.$_SERVER['SERVER_PROTOCOL']."\n"; 
	foreach($this->headers as $k => $v) {
		// if ($k==="isself"){
		// 	continue;
		// }
		$tmp .= $k . ': ' . $v . "\n";
	}
	if (!empty($this->request_data)) {
		$tmp .= "\n". $this->request_data . "\n";
	}
	$tmp .= "\nResponse\n";
	$tmp .= $this->response_content;
	file_put_contents($this->logdir.'flag_log.txt', $tmp, FILE_APPEND | LOCK_EX);
	if (filesize($this->logdir . 'flag_log' . '.txt') > $config->max_log_size) {
		unlink($this->logdir . 'flag_log' . '.txt');
	}
}

}
function getMillisecond(){
	list($s1,$s2)=explode(' ',microtime());
	return (float)sprintf('%.0f',(floatval($s1)+floatval($s2))*1000);
}
// 还原 rfc1867, rfc2046 格式的FormData, 来自https://blog.izgq.net/archives/1029/
function getFormData(){
	// body-part array
	$body = array();

	// 普通参数
	foreach ($_POST as $key => $value) {
		if (!is_array($value)) {
			$body_part = "Content-Disposition: form-data; name=\"$key\"\r\n";
			$body_part .= "\r\n$value";
			$body[] = $body_part;
		} else {
			// 数组的情况处理 如 param1[]=xxxx
			$result = array();
			convert_array_key($value, $key, $result);
			foreach ($result as $k => $v) {
				$body_part = "Content-Disposition: form-data; name=\"$k\"\r\n";
				$body_part .= "\r\n$v";
				$body[] = $body_part;
			}
		}
	}

	// 上传文件处理
	foreach ($_FILES as $key => $value) {
		if (!is_array($value['type'])) {
			$body_part = "Content-Disposition: form-data; name=\"$key\"; filename=\"{$value['name']}\"\r\n";
			$body_part .= "Content-type: {$value['type']}\r\n";
			$body_part .= "\r\n" . file_get_contents($value['tmp_name']);
			$body[] = $body_part;
		} else {
			// 文件key是数组的情况 如 file1[]=xxxx
			$result = array();
			convert_array_key($value['type'], "", $result);
			foreach ($result as $k => $v) {
				$filename = query_multidimensional_array($value['name'], $k);
				$type = query_multidimensional_array($value['type'], $k);
				$tmp_name = query_multidimensional_array($value['tmp_name'], $k);
				$body_part = "Content-Disposition: form-data; name=\"{$key}{$k}\"; filename=\"{$filename}\"\r\n";
				$body_part .= "Content-type: {$type}\r\n";
				$body_part .= "\r\n" . file_get_contents($tmp_name);
				$body[] = $body_part;
			}
		}
	}

	// 提取boundary
	$boundary = substr($_SERVER['CONTENT_TYPE'], strpos($_SERVER['CONTENT_TYPE'], "=") + 1);
	// multipart-body
	$multipart_body = "--$boundary\r\n";
	// 拼接各个域
	$multipart_body .= implode("\r\n--$boundary\r\n", $body);
	// 最后一个不同的 boundary
	$multipart_body .= "\r\n--$boundary--";

	return $multipart_body;
}

// 直接访问多维数组元素
// query: [0][0] -> $array[0][0]
function query_multidimensional_array(&$array, $query){
	$query = explode('][', substr($query, 1, -1));
	$temp = $array;
	foreach ($query as $key) {
		$temp = $temp[$key];
	}
	return $temp;
}

// DFS将数组变为一维形式
function convert_array_key(&$node, $prefix, &$result){
	if (!is_array($node)) {
		$result[$prefix] = $node;
	} else {
		foreach ($node as $key => $value) {
			convert_array_key($value, "{$prefix}[{$key}]", $result);
		}
	}
}

if (!function_exists('getallheaders'))
{
    function getallheaders()
    {
           $headers = [];
       foreach ($_SERVER as $name => $value)
       {
           if (substr($name, 0, 5) == 'HTTP_'&&$value!='')
           {
               $headers[str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($name, 5)))))] = $value;
           }
       }
       return $headers;
    }
}
function decode_chunked($str)	//	https://stackoverflow.com/a/10859409
{
	for ($res = ''; !empty($str); $str = trim($str)) {
		$pos = strpos($str, "\r\n");
		$len = hexdec(substr($str, 0, $pos));
		$res .= substr($str, $pos + 2, $len);
		$str = substr($str, $pos + 2 + $len);
	}
	return $res;
}

class ui
{
	public $passwdhash;
	public $mdui_css = <<<CSS_RESOURCE
{{@res-file:mdui.min.css}}
CSS_RESOURCE;
	public $mdui_js = <<<JS_RESOURCE
{{@res-file:mdui.min.js}}
JS_RESOURCE;
	public $mdui_logo = <<<SVG_RESOURCE
{{@res-file:logo.svg}}
SVG_RESOURCE;
	public $mdui_font = '';
	function __construct()
	{
		$this->mdui_font = base64_decode('{{@res-file:mdui-icon.woff2.base64}}');
	}
	function show()
	{
		global $config;
		// die(var_dump(get_object_vars($config)));
		if ($this->passwdhash === 'unset'){
			if (isset($_GET['passwd'])){
				if (trim($_GET['passwd'] === "")){
					die('密码不能为空');
				}
				$config->change('password_sha1', sha1($_GET['passwd']));
				die('密码初始化成功');
			}
		}
		if (sha1($_GET['passwd']) == $this->passwdhash) {
			$_SESSION['login'] = 'success';
			echo "login success.";
		}
		if ($_SESSION['login'] !== 'success') {
			$this->login();
		}
		print(<<<HTML_CODE
        <html>
            <head>
				<title>Watchbird控制台</title>
				<link rel="shortcut icon" href="?watchbird=resource&resource=logo">
                <link rel="stylesheet" href="?watchbird=resource&resource=css">
				<script src="?watchbird=resource&resource=js"></script>
				<style>
*{font-family: Arial, Helvetica, sans-serif;}
textarea{font-family: monospace !important;}
.logger .mdui-col {
  margin: 20px 20px;
  max-width: 45%;
  min-width: 400px;
  height: 45%;
}
.logcontainer .mdui-card{
  margin-top: 10px;
  transition: 0.6s;
  opacity: 0;
}
.logcontainer .mdui-card.active{
  opacity: 1;
}
.logger div.mdui-col{
  overflow: auto;
}
.dest-selector-multi{
  min-width: 42px;
}
pre{
  font-family: Arial, Helvetica, sans-serif;
  font-weight: 300;
  white-space: pre-wrap;
  word-break: break-all;
  padding-left: 10px;
  padding-right: 10px;
}
*{
  scrollbar-width: thin;
  scrollbar-color: #cdcdcd rgba(0,0,0,0)
}
				</style>
				<script>
					function sleep(ms) {
						return new Promise(resolve => setTimeout(resolve, ms));
					}
                    function switchdrawer() {
                        var inst = new mdui.Drawer(document.getElementsByClassName("mdui-drawer")[0]);
                        inst.toggle();
                    }

					function getLocalConfig(ConfigItem){
						var ret = localStorage.getItem(ConfigItem);
						return ret;
					}

					function setLocalConfig(ConfigItem, value) {
						return localStorage.setItem(ConfigItem, value);
					}

                    function changetheme() {
                        var body = document.querySelector("body");
                        var res = body.classList.replace("mdui-theme-layout-dark", "mdui-theme-primary-teal");
                        if (!res){
                            body.classList.replace("mdui-theme-primary-teal", "mdui-theme-layout-dark");
                            body.classList.remove("mdui-theme-accent-pink");
                            setLocalConfig("theme", "dark");
                        }
                        else{
                            body.classList.add("mdui-theme-accent-pink");
                            setLocalConfig("theme", "light");
                        }
                    }
					async function checkLocalReplayerAvailablility(){
						await fetch(document.getElementById("replayer_addr").value + "?watchbird=checkExistence")
							.then(function(Response) {
								return Response.text()
							})
							.then(function(txt) {
								if (txt == "I'm still alive"){
									document.getElementById("use_custom_replayer").checked = true;
								}
							})
					}
                    document.addEventListener("DOMContentLoaded",function () {
                        if (getLocalConfig("theme") == "dark"){
                            changetheme();
						}
						if (getLocalConfig("submit_packet_body") != null){
                            document.getElementById("submit_packet_body").value = getLocalConfig("submit_packet_body");
						}
						if (getLocalConfig("submit_packet_header") != null){
                            document.getElementById("submit_packet_header").value = getLocalConfig("submit_packet_header");
						}
						if (getLocalConfig("flag_regex") != null){
                            document.getElementById("flag_regex").value = getLocalConfig("flag_regex");
						}
						if (getLocalConfig("replayer_addr") != null){
                            document.getElementById("replayer_addr").value = getLocalConfig("replayer_addr");
						}
						startDaemon();
						startKillallTimer();
						Notification.requestPermission().then(function (permission) {
							if (permission === 'granted') {
								console.log('用户允许通知');
							} else if (permission === 'denied') {
								console.log('用户拒绝通知');
							}
						});
						checkLocalReplayerAvailablility();
                    });
					async function startKillallTimer(){
						document.getElementById("config_scheduled_killall").nextElementSibling.nextSibling.textContent = "每分钟自动关闭所有Web进程并清理Crontab";
						document.getElementById("config_scheduled_killall").nextElementSibling.style.marginRight = "12px";
						while(1){
							await sleep(60000);
							if (document.getElementById("config_scheduled_killall").checked){
								await fetch("?watchbird=scheduled_killall");
							}
						}
					}
					async function startDaemon(){
						while(1){
							try{
								await checklog();
							}
							catch{continue;}
							await sleep(1000);
						}
					}
					function parseRequest(text){
						text = text.substring(text.search("SRC IP"));
						text = text.substring(text.search("\\n")).trim();
						if (text.search("\\n\\nResponse") != -1){
						 	text = text.substring(0, text.search("\\n\\nResponse"));	//Dont forget that you're in PHP!
						}
						return text;
					}
					function addlistitem(str){
						var newtextfield = document.createElement("div");
						newtextfield.classList.add("mdui-textfield");
						var textInput = document.createElement("textarea");
						textInput.classList.add("mdui-textfield-input");
						textInput.value = str;
						textInput.spellcheck = false;
						newtextfield.append(textInput);
						document.getElementsByClassName("repeater")[0].getElementsByClassName("header-field")[0].append(newtextfield);
					}
					function handle_replay(){
						var text = event.target.parentElement.previousElementSibling.innerText;
						document.getElementsByClassName("repeater")[0].getElementsByClassName("header-field")[0].innerHTML = "";
						text = parseRequest(text);
						try{
							document.getElementById("myhost").value = text.match(new RegExp("host: {0,}[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}", 'i'))[0].match(new RegExp("[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}"))[0];
						}
						catch{}
						var postdata = "undefined";
						var text_search_nn = text.search("\\n\\n");
						if (text_search_nn != -1){
							postdata = text.substring(text_search_nn+2);
							text = text.substring(0, text_search_nn);
						}
						var queryList = text.split("\\n");
						for (var i = 0;i < queryList.length;i++){
							addlistitem(queryList[i]);
						}
						if (postdata != "undefined"){
							addlistitem(postdata);
							var newlabel = document.createElement("label");
							newlabel.classList.add("mdui-textfield-label");
							newlabel.innerText = "POST data";
							document.getElementsByClassName("repeater")[0].getElementsByClassName("header-field")[0].lastElementChild.prepend(newlabel);
						}
						var inst = new mdui.Dialog(document.getElementsByClassName("repeater")[0]);
						inst.open();
						mdui.mutation();
					}
					async function submitFlag(flag){
						var submit_packet_header = document.getElementById("submit_packet_header").value;
						var submit_packet_body = document.getElementById("submit_packet_body").value;
						var headerList = submit_packet_header.split("\\n");
						var finalPacket = "";
						var isPost = (submit_packet_body.trim().length != 0);
						var ipAddr = "";
						var port = "80";
						for (var i = 0;i < headerList.length; i++){
							if (headerList[i].search(new RegExp("^content-length:", 'i')) != -1){continue;}
							if (headerList[i].search(new RegExp("^connection:", 'i')) != -1){continue;}
							if (!isPost && headerList[i].search(new RegExp("^content-type:", 'i')) != -1){continue;}
							if (!isPost && headerList[i].search(new RegExp("^accept-encoding:", 'i')) != -1){continue;}
							if (headerList[i].search(new RegExp("^host:", 'i')) != -1){
								ipAddr = headerList[i].trim().split(":")[1].trim();
								try{
									port = headerList[i].trim().split(":")[2].trim();
									if (port == undefined) {port = "80"};
								}
								catch{}
							}
							finalPacket += headerList[i].trim();
							finalPacket += "\\r\\n";
						}
						finalPacket += "Connection: close\\r\\n";
						finalPacket += "Accept-Encoding: identity\\r\\n";
						if (isPost){
							finalPacket += "Content-Length: " + submit_packet_body.length;
							finalPacket += "\\r\\n\\r\\n";
							finalPacket += submit_packet_body;
						}
						else{
							finalPacket += "\\r\\n";
						}
						var ret = "";
						if (submit_packet_header.search("x-www-form-urlencoded") != -1){
							flag = escape(flag);
						}
						finalPacket = finalPacket.replace("{flag_content}", flag);
						await fetch("?watchbird=replay&ip="+ipAddr+"&port="+port, {
							body: finalPacket,
							method: 'POST',
						}).then(function(response) {
							return response.text();
						}).then(async function(resp) {
							ret = resp;
						});
						ret = ret.substring(ret.search("\\r\\n\\r\\n") + 4);
						return ret;
					}
					async function sendSinglePacket(ip, port, packet){
						if (document.getElementById("passhost").checked && (ip+":"+port == document.getElementById("myhost").value ||( ip == document.getElementById("myhost").value && port == 80))){
							var newcard = document.createElement("div");
							newcard.classList.add("mdui-card");
							newcard.style.maxHeight = 600;
							newcard.style.overflow = "scroll";
							var newcard_primary = document.createElement("div");
							newcard_primary.classList.add("mdui-card-primary");
							var subtitle = document.createElement("div");
							subtitle.classList.add("mdui-card-primary-subtitle");
							subtitle.style.width = 120;
							subtitle.style.paddingRight = 0;
							subtitle.innerHTML = ip+":"+port;
							newcard_primary.append(subtitle);
							var cardcontent = document.createElement("div");
							cardcontent.classList.add("mdui-card-content");
							cardcontent.innerText = "已跳过当前主机";
							newcard.append(newcard_primary);
							newcard.append(cardcontent);
							newcard.style.transition = "all .3s linear 0s"
							newcard.style.display = "flex";
							newcard.style.opacity = 0;
							document.getElementsByClassName("responsebox")[0].prepend(newcard);
							await sleep(10);
							document.getElementsByClassName("responsebox")[0].firstElementChild.style.opacity = 1;
							return;
						}
						if (document.getElementById("modifyHost").checked){
							if (packet.search(new RegExp('host: {0,}[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}:[0-9]{1,5}', 'i')) != -1){
								packet = packet.replace(new RegExp('host: {0,}[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}:[0-9]{1,5}', 'i'), 'Host: '+ip+":"+port);
							}
							else{
								packet = packet.replace(new RegExp('host: {0,}[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}', 'i'), 'Host: '+ip+":"+port);
							}
						}
						var FinalFetchUrl = "?watchbird=replay&ip="+ip+"&port="+port;
						if (document.getElementById("use_custom_replayer").checked){
							FinalFetchUrl = document.getElementById("replayer_addr").value + FinalFetchUrl;
						}
						await fetch(FinalFetchUrl, {
							body: packet,
							method: 'POST',
						}).then(function(response) {
							return response.text();
						}).then(async function(resp) {
							var newcard = document.createElement("div");
							newcard.classList.add("mdui-card");
							newcard.style.maxHeight = 600;
							newcard.style.overflow = "scroll";
							var newcard_primary = document.createElement("div");
							newcard_primary.classList.add("mdui-card-primary");
							var subtitle = document.createElement("div");
							subtitle.classList.add("mdui-card-primary-subtitle");
							subtitle.style.width = 120;
							subtitle.style.paddingRight = 0;
							subtitle.innerHTML = ip+":"+port;
							newcard_primary.append(subtitle);
							var flag_regex = document.getElementById("flag_regex").value;
							var flag_content = resp.match(new RegExp(flag_regex));
							var submitResult = "";
							if (flag_content != null && flag_content[0].trim() != ""){
								var subtitle2 = document.createElement("div");
								subtitle2.classList.add("mdui-card-primary-subtitle");
								subtitle2.style.width = 120;
								subtitle2.style.paddingRight = 0;
								subtitle2.style.wordWrap = "anywhere";
								subtitle2.innerText = flag_content[0];
								if (document.getElementById("flag_auto_submit").checked){
									console.log(ip+":"+port+"    "+flag_content[0]);
									submitResult = await submitFlag(flag_content[0]);
									subtitle2.innerText += "\\n" + submitResult;
								}
								newcard_primary.append(subtitle2);
							}
							var cardcontent = document.createElement("div");
							cardcontent.classList.add("mdui-card-content");
							if (resp.trim() == ""){
								resp = "服务器无响应";
							}
							cardcontent.innerText = resp;
							newcard.append(newcard_primary);
							newcard.append(cardcontent);
							newcard.style.transition = "all .3s linear 0s"
							newcard.style.display = "flex";
							newcard.style.opacity = 0;
							document.getElementsByClassName("responsebox")[0].prepend(newcard);
							await sleep(10);
							document.getElementsByClassName("responsebox")[0].firstElementChild.style.opacity = 1;
						});
					}
					var replayRunning = false;
					async function replaypacket(){
						if (replayRunning){
							replayRunning = false;
							event.target.innerText = "Stoping..";
							event.target.disabled = true;
							return;
						}
						replayRunning = true;
						var target = event.target;
						target.innerText = "Stop";
						var packet = "";
						var listcount = document.getElementsByClassName("header-field")[0].childElementCount;
						for (var i = 0;i < listcount - 1;i++){
							var val = document.getElementsByClassName("header-field")[0].childNodes[i].lastElementChild.value;
							if (val.search(new RegExp("connection:", 'i')) != -1) {continue;}
							if (val.search(new RegExp("accept-encoding:", 'i')) != -1) {continue;}
							packet += val;
							packet += "\\r\\n";
						}
						packet += "Accept-Encoding: identity\\r\\n";
						packet += "Connection: close\\r\\n";
						if (document.getElementsByClassName("header-field")[0].childNodes[listcount-1].childElementCount > 1){
							// it is a POST packet
							packet += "\\r\\n";
							packet += document.getElementsByClassName("header-field")[0].childNodes[listcount - 1].lastElementChild.value;
							packet = packet.replace(new RegExp("Content-Length: [0-9]{1,}", 'i'), "Content-length: "+document.getElementsByClassName("header-field")[0].childNodes[listcount - 1].lastElementChild.value.length);
						}
						else{
							packet += document.getElementsByClassName("header-field")[0].childNodes[listcount - 1].lastElementChild.value;
							packet += "\\r\\n\\r\\n";
						}
						document.getElementsByClassName("repeater")[0].style.width = 1500;
						document.getElementsByClassName("repeater")[0].style.maxWidth = "95%";
						if(document.body.clientWidth > 500){
							document.getElementsByClassName("repeater")[0].classList.add("mdui-row-xs-2");
						}
						else {
							document.getElementsByClassName("repeater")[0].style.overflow = "scroll";
						}
						document.getElementsByClassName("responsebox")[0].style.display = "block";
						document.getElementsByClassName("responsebox")[0].prepend(document.createElement("br"));
						var newdelimiter = document.createElement("div");
						newdelimiter.classList.add("mdui-divider");
						document.getElementsByClassName("responsebox")[0].prepend(newdelimiter);
						document.getElementsByClassName("responsebox")[0].prepend(document.createElement("br"));
						setLocalConfig("submit_packet_header", document.getElementById("submit_packet_header").value);
						setLocalConfig("submit_packet_body", document.getElementById("submit_packet_body").value);
						setLocalConfig("flag_regex", document.getElementById("flag_regex").value);
						setLocalConfig("replayer_addr", document.getElementById("replayer_addr").value);
						var domInputNodes = document.getElementsByClassName("dest-selector-multi");
						var ip_part1_start = domInputNodes[0].querySelectorAll("input")[0].value - 0;
						var ip_part1_end = domInputNodes[0].querySelectorAll("input")[1].value - 0;
						var ip_part2_start = domInputNodes[1].querySelectorAll("input")[0].value - 0;
						var ip_part2_end = domInputNodes[1].querySelectorAll("input")[1].value - 0;
						var ip_part3_start = domInputNodes[2].querySelectorAll("input")[0].value - 0;
						var ip_part3_end = domInputNodes[2].querySelectorAll("input")[1].value - 0;
						var ip_part4_start = domInputNodes[3].querySelectorAll("input")[0].value - 0;
						var ip_part4_end = domInputNodes[3].querySelectorAll("input")[1].value - 0;
						var ipstep = domInputNodes[5].querySelectorAll("input")[0].value - 0;
						var port_start = domInputNodes[8].querySelectorAll("input")[0].value - 0;
						var port_end = domInputNodes[8].querySelectorAll("input")[1].value - 0;
						var port_step = domInputNodes[10].querySelectorAll("input")[0].value - 0;
						for (var i = ip_part1_start;i<=ip_part1_end;i+=ipstep){
							for (var j = ip_part2_start;j<=ip_part2_end;j+=ipstep){
								for (var k = ip_part3_start;k<=ip_part3_end;k+=ipstep){
									for (var l = ip_part4_start;l<=ip_part4_end;l+=ipstep){
										for (var m = port_start;m<=port_end;m+=port_step){
											if (replayRunning){
												await sendSinglePacket(i.toString()+'.'+j+'.'+k+'.'+l, m, packet);
												new mdui.Dialog(document.getElementsByClassName("repeater")[0]).handleUpdate()
											}else{
												target.innerText = "Go!";
												target.disabled = false;
												break;
											}
										}
									}
								}
							}
						}
						replayRunning = false;
						target.innerText = "GO!";
						target.disabled = false;
					}
                    function changevalue_switch(){
                        var val = event.target.checked+0;
                        fetch("?watchbird=change&key="+event.target.id.substring(7).trim()+"&value="+val);
                    }
                    function changevalue_text(){
                        var target = event.target;
                        if (event.target.classList.contains("mdui-icon")){
                            target = event.target.parentElement;
                        }
                        var key = target.parentElement.firstChild.firstChild.textContent.trim();
                        var val = target.parentElement.firstChild.lastChild.value;
                        fetch("?watchbird=change&key="+key+"&value="+escape(val));
					}
					function showmodule(e){
						document.getElementById(document.getElementsByClassName('mdui-typo-title')[0].innerHTML).classList.replace("mdui-not-hidden", "mdui-hidden");
						document.getElementById(e).classList.replace("mdui-hidden", "mdui-not-hidden");
						document.getElementsByClassName('mdui-typo-title')[0].innerHTML = e;
					}
					async function sendnoti(tit, msg){
						Notification.requestPermission().then(function (permission) {
							if (permission === 'granted') {
								var n = new Notification(tit, {
									body: msg,
									icon: '?watchbird=resource&resource=logo'
								});
							} else if (permission === 'denied') {
								console.log('用户拒绝通知');
							}
						});
						mdui.snackbar({
							message: tit,
							timeout: 500,
							position: "right-top"
						});
						await sleep(500);
					}
					async function addlog(doReplay, module, str, id){
						if (module == 'flag_log' && timestampflag_log > 0){
							await sendnoti('深度防御拦截了一次有效攻击', '查看flag_log以获取详细信息');
						}
						if (module == "under_attack_log"){
							if (timestampunder_attack_log > 0){
								await sendnoti('RCE防护拦截了一次有效攻击', '查看under_attack_log以获取详细信息');
							}
							var cpydiv = document.getElementById("web_log" + id).cloneNode(true);
							cpydiv.id = module + id;
							cpydiv.classList.remove("active");
							cpydiv.querySelector("button").onclick = function () { handle_replay(); }
							document.getElementById(module).getElementsByClassName("logcontainer")[0].prepend(cpydiv);
							mdui.mutation();
							await sleep(20);
							cpydiv.classList.add("active");
							return;
						}
						var newdivrow = document.createElement("div");
						newdivrow.id = module+id;
						newdivrow.classList.add("mdui-card")
						newdivrow.classList.add("mdui-hoverable")
						if (doReplay){
							var newdivcol = document.createElement("div")
							newdivcol.classList.add("mdui-card-actions")
							var but = document.createElement("button");
							but.classList.add("mdui-btn");
							but.classList.add("mdui-ripple");
							but.classList.add("mdui-btn-raised")
							but.classList.add("mdui-color-theme-accent");
							but.onclick = function(){handle_replay();}
							but.innerText = "重放"
							newdivcol.append(but)
						}
						var code = document.createElement("pre")
						code.innerText = str.trim();
						newdivrow.append(code);
						if (doReplay){
							newdivrow.append(newdivcol);
						}
						document.getElementById(module).getElementsByClassName("logcontainer")[0].prepend(newdivrow)
						mdui.mutation();
						await sleep(20);
						newdivrow.classList.add("active");
					}
					var timestampflag_eye_to_eye = 0;
					var timestampflag_log = 0;
					var timestampall_requests = 0;
					var timestampunder_attack_log = 0;
					var timestampweb_log = 0;

					async function checklog(){
						var modulelist = ['web_log', 'under_attack_log', 'flag_eye_to_eye', 'flag_log'];
						for (var co = 0 ;co<modulelist.length;co++){
							var module = modulelist[co];
							var doReplay = true;
							if (!document.getElementById(module).querySelector("label").firstElementChild.checked){
								continue;
							}
							if (module == "all_requests"){doReplay = false;}
							var isNew = true;
							await fetch("?watchbird=log&module="+module+"&timestamp="+eval('timestamp'+module))
							.then(function(response) {
								return response.json();
							})
							.then(async function(myJson) {
								for (var i = 0 ;i<myJson.length;i+=2){
									try{
										await addlog(doReplay, module, myJson[i], myJson[i+1]);
									}
									catch{};
								}
								if (myJson.length > 1){
									eval('timestamp' + module + "=" + myJson[myJson.length - 1]);
								}
								else if (co == 0){
									isNew = false;
								}
							});
							if (!isNew){return;}
							if (eval('timestamp' + module) == 0){
								eval('timestamp' + module + "=1");
							}
						}
						await fetch("?watchbird=checkupload")
						.then(function(response) {
							return response.json();
						})
						.then(async function(myJson) {
							if(myJson["auth"] == true && myJson["change"] == true){
								await sendnoti('文件上传防御拦截了一次攻击', '请查看/tmp/watchbird/upload文件夹或设置的文件夹');
							}
						});
					}
					async function handlePanelUpdate(){
						for (var i = 0;i<50;i++){
							new mdui.Dialog(document.getElementsByClassName("repeater")[0]).handleUpdate();
							await sleep(3);
						}
					}
                </script>
            </head>
            <body class="mdui-appbar-with-toolbar mdui-loaded mdui-drawer-body-left mdui-theme-primary-teal mdui-theme-accent-pink">
                <div class="mdui-appbar mdui-appbar-fixed">
                    <div class="mdui-toolbar mdui-color-theme">
                        <a onclick="switchdrawer();" class="mdui-btn mdui-btn-icon"><i class="mdui-icon material-icons">menu</i></a>
                        <a href="javascript:;" class="mdui-typo-headline">Watchbird控制台</a>
                        <a href="javascript:;" class="mdui-typo-title">配置</a>
                        <div class="mdui-toolbar-spacer"></div>
                        <a onclick="changetheme();" class="mdui-btn mdui-btn-icon"><i class="mdui-icon material-icons">color_lens</i></a>
                        <a onclick="location.reload();" class="mdui-btn mdui-btn-icon"><i class="mdui-icon material-icons">refresh</i></a>
                    </div>
                </div>
                <!-- 默认抽屉栏在左侧 -->
                <div class="mdui-drawer mdui-list mdui-shadow-10">
                    <a onclick="showmodule('配置');"  class="mdui-list-item mdui-ripple ">
                        <i class="mdui-list-item-icon mdui-icon material-icons">settings</i>
                        <div class="mdui-list-item-content">配置</div>
                    </a>
                    <a onclick="showmodule('日志');" class="mdui-list-item mdui-ripple ">
                        <i class="mdui-list-item-icon mdui-icon material-icons">library_books</i>
                        <div class="mdui-list-item-content">日志</div>
					</a>
					<a mdui-dialog="{target: '#repeater'}" class="mdui-list-item mdui-ripple">
                        <i class="mdui-list-item-icon mdui-icon material-icons">send</i>
                        <div class="mdui-list-item-content">重放</div>
                    </a>
                </div>
                <div id="配置" class="mdui-container mdui-not-hidden doc-container">
                    <div class="mdui-row-md-2">
HTML_CODE
);

		foreach (get_object_vars($config) as $key => $val) {
			if ($val === 0) {
				print('<div class="mdui-col"><label class="mdui-switch">
  <input id="config_' . $key . '" onclick="changevalue_switch();" type="checkbox"/>
  <i class="mdui-switch-icon"></i>&nbsp;&nbsp;&nbsp;&nbsp;' . $key . '
</label></div>');
			}
			if ($val === 1) {
				print('<div class="mdui-col"><label class="mdui-switch">
  <input id="config_' . $key . '" onclick="changevalue_switch();" type="checkbox" checked />
  <i class="mdui-switch-icon"></i>&nbsp;&nbsp;&nbsp;&nbsp;' . $key . '
</label></div>');
			}
		}
		print('</div>');
		foreach (get_object_vars($config) as $key => $val) {
			if ($val !== 0 && $val !== 1) {
				print('<div class="mdui-row"><div class="mdui-textfield mdui-col-xs-10">' . $key . '
  <textarea class="mdui-textfield-input" type="text" spellcheck="false">' . $val . '</textarea></div><p>&nbsp;</p><button onclick="changevalue_text();" class="mdui-btn mdui-btn-icon mdui-btn-raised mdui-color-theme-accent mdui-ripple"><i
        class="mdui-icon material-icons">save</i></button></div>');
			}
		}
		print('</div>');
		print(<<<HTML_CODE
		<div id="日志" class="mdui-container mdui-hidden doc-container mdui-row-xs-2 logger">
			<div id="flag_eye_to_eye" class="mdui-shadow-5 mdui-col mdui-hoverable ">
				<p style="width: 60%;display: inline-flex;left: 20px;position: relative;">flag_eye_to_eye</p>
				<label class="mdui-checkbox">
					<input type="checkbox" checked />
					<i class="mdui-checkbox-icon"></i>
					自动更新
				</label>
				<div class="mdui-divider"></div>
				<div class="mdui-container-fluid logcontainer">
				</div>
			</div>
			<div id="flag_log" class="mdui-shadow-5 mdui-col mdui-hoverable ">
				<p style="width: 60%;display: inline-flex;left: 20px;position: relative;">flag_log</p>
				<label class="mdui-checkbox"">
					<input type="checkbox" checked />
					<i class="mdui-checkbox-icon"></i>
					自动更新
				</label>
				<div class="mdui-divider"></div>
				<div class="mdui-container-fluid logcontainer">
				</div>
			</div>
			<div id="under_attack_log" class="mdui-shadow-5 mdui-col mdui-hoverable ">
				<p style="width: 60%;display: inline-flex;left: 20px;position: relative;">under_attack_log</p>
				<label class="mdui-checkbox">
					<input type="checkbox" checked />
					<i class="mdui-checkbox-icon"></i>
					自动更新
				</label>
				<div class="mdui-divider"></div>
				<div class="mdui-container-fluid logcontainer">
				</div>
			</div>
			<div id="web_log" class="mdui-shadow-5 mdui-col mdui-hoverable ">
				<p style="width: 60%;display: inline-flex;left: 20px;position: relative;">web_log</p>
				<label class="mdui-checkbox">
					<input type="checkbox" disabled checked />
					<i class="mdui-checkbox-icon"></i>
					自动更新
				</label>
				<div class="mdui-divider"></div>
				<div class="mdui-container-fluid logcontainer">
				</div>
			</div>
		</div>
		<div id="repeater" class="mdui-dialog repeater" style="transition: all .15s linear 0s;">
			<div class="mdui-dialog-content mdui-col" style="scrollbar-width: none;">
				<div class="mdui-dialog-title mdui-row" style="display: flex;">
					<div class="mdui-col-xs-2">重放</div>
					<div class="mdui-col-xs-8 mdui-row" style="height: 10px;">
						<label class="mdui-col-xs-3 mdui-checkbox">
							<input id="modifyHost" type="checkbox" checked/>
							<i class="mdui-checkbox-icon"></i>
							<small style="margin-left: 15px;" class="mdui-textfield-label">修改Host</small>
						</label>
						
						<label class="mdui-col-xs-1 mdui-checkbox">
							<input id="passhost" type="checkbox" checked/>
							<i class="mdui-checkbox-icon"></i>
						</label>
						<div class="mdui-col-xs-3 mdui-textfield" style="padding: 0;margin-top: -10px;">
							<label class="mdui-textfield-label">跳过该Host</label>
							<input id="myhost" class="mdui-textfield-input" type="text" style="height: 30px;" />
						</div>

						<label class="mdui-col-xs-1 mdui-checkbox" style="right:-10px">
							<input id="use_custom_replayer" type="checkbox"/>
							<i class="mdui-checkbox-icon"></i>
						</label>
						<div class="mdui-col-xs-4 mdui-textfield" style="padding: 0;margin-top: -10px;" title="使用存在本地web服务器的watchbird发包, 应对靶机间不能互联的情况. 使用方法: 将watchbird.php放在本地服务器的根目录, 或一个任意目录, 然后修改本地发包器的值. 本选项默认关闭, 将在检测到本地发包器存在时自动开启.">
							<label class="mdui-textfield-label">本地发包器</label>
							<input id="replayer_addr" class="mdui-textfield-input" type="text" style="height: 30px;" value="http://127.0.0.1/watchbird.php"/>
						</div>
					</div>
					<button onclick="replaypacket();" class="mdui-btn mdui-btn-raised mdui-ripple mdui-col-xs-1 mdui-color-theme-accent">Go!</button>
				</div>
				<div class="mdui-row">
					<div class="mdui-panel mdui-panel-gapless" mdui-panel>

						<div class="mdui-panel-item">
							<div onclick='handlePanelUpdate();' class="mdui-panel-item-header mdui-row">
								<div class="mdui-valign mdui-col-xs-10">
									<label><button class="mdui-btn mdui-btn-icon mdui-ripple"><i class="mdui-icon material-icons">settings</i></button></label>Flag自动提交
								</div>
								<div class="mdui-valign mdui-col-xs-2">
									<label class="mdui-checkbox">
										<input id="flag_auto_submit" type="checkbox"/>
										<i class="mdui-checkbox-icon"></i>
										<p style="margin-top: -2px;margin-left: -5px;">启用</p>
									</label>
								</div>
							</div>
							<div class="mdui-panel-item-body">
								<div class="mdui-textfield">
									<label class="mdui-textfield-label">Flag正则</label>
									<textarea id="flag_regex" class="mdui-textfield-input" type="text" >flag\\{[0-9, a-z]{12,64}\\}</textarea>
								</div>
								<div class="mdui-textfield">
									<label class="mdui-textfield-label">提交给flag机的数据包, 用{flag_content}表示flag内容</label>
									<textarea id="submit_packet_header" class="mdui-textfield-input" spellcheck="false" type="text">POST /check?uuid=leohearts HTTP/1.1\nHost: 192.168.1.1\nCookie: PHPSESSID=vdcie5nmh19vioc5s1m02eq9d9\nContent-Length: 0\nAccept: */*\nConnection: close\nContent-Type: application/x-www-form-urlencoded</textarea>
								</div>
								<div class="mdui-textfield">
									<label class="mdui-textfield-label">POST数据, 可留空</label>
									<textarea id="submit_packet_body" class="mdui-textfield-input" spellcheck="false" type="text">flag={flag_content}</textarea>
								</div>
								
							</div>
						</div>
					</div>
				</div>
				<div class="dest-selector mdui-row" style="text-align:center;">
					<div class="dest-selector-multi mdui-col-xs-1">
						<div class="mdui-textfield">
							<input class="mdui-textfield-input" type="text" placeholder="ip.start" value="192"/>
						</div>
						<div class="mdui-textfield">
							<input class="mdui-textfield-input" type="text" placeholder="ip.end" value="192"/>
						</div>
					</div>
					<div class="dest-selector-multi mdui-col-xs-1">
						<div class="mdui-textfield">
							<input class="mdui-textfield-input" type="text" value="168"/>
						</div>
						<div class="mdui-textfield">
							<input class="mdui-textfield-input" type="text" value="168"/>
						</div>
					</div>
					<div class="dest-selector-multi mdui-col-xs-1">
						<div class="mdui-textfield">
							<input class="mdui-textfield-input" type="text" value="1"/>
						</div>
						<div class="mdui-textfield">
							<input class="mdui-textfield-input" type="text" value="1"/>
						</div>
					</div>
					<div class="dest-selector-multi mdui-col-xs-1">
						<div class="mdui-textfield">
							<input class="mdui-textfield-input" type="text" value="1"/>
						</div>
						<div class="mdui-textfield">
							<input class="mdui-textfield-input" type="text" value="100"/>
						</div>
					</div>
					<div class="dest-selector-multi mdui-col-xs-1" style="min-width: 0px;"></div>
					<div class="dest-selector-multi mdui-col-xs-1">
						<div class="mdui-textfield">
							<input class="mdui-textfield-input" type="text" value="1" />
							<label class="mdui-textfield-label">步进</label>
						</div>
					</div>
					<div class="dest-selector-multi mdui-col-xs-1" style="min-width: 0;"></div>
					<div class="dest-selector-multi mdui-col-xs-1" style="min-width: 0;"></div>
					<div class="dest-selector-multi mdui-col-xs-1">
						<div class="mdui-textfield">
							<input class="mdui-textfield-input" type="text" placeholder="port.start" value="80"/>
						</div>
						<div class="mdui-textfield">
							<input class="mdui-textfield-input" type="text" placeholder="port.end"
							value="80"/>
						</div>
					</div>
					<div class="dest-selector-multi mdui-col-xs-1" style="min-width: 0;"></div>
					<div class="dest-selector-multi mdui-col-xs-1" style="right: 0;position: absolute;">
						<div class="mdui-textfield">
							<input class="mdui-textfield-input" type="text" value="1" />
							<label class="mdui-textfield-label">步进</label>
						</div>
					</div>
				</div>
				<div class="header-field"></div>
			</div>
			<div class="mdui-dialog-content mdui-col responsebox" style="display: none;"></div>
		</div>
HTML_CODE
		);
		print('
            </body>
        </html>');
	}
	function login()
	{
		echo(<<<HTML_CODE
        <html>
            <head>
                <title>Login - Watchbird</title>
                <link rel="stylesheet" href="?watchbird=resource&resource=css">
                <script src="?watchbird=resource&resource=js"></script>
                <script>
                    function login() {
                        var passwd = document.querySelector("input").value;
                        fetch("?watchbird=ui&passwd=" + passwd).then(function (resp) {
                            location.reload();
                        });
                    }
                    document.onkeydown = function (event) {
                        if (event.key == 'Enter') {
                            login();
                        }
                    }
                </script>
                <style>
.loginform {
  width: 400px;
  height: 200px;
  display: block;
  margin: 30 auto;
  box-shadow: 5px 5px 5px 5px gray;
  border-radius: 10px;
  padding: 20px;
  padding-top: 10px;
  background-color: #33aaff;
  color: white;
}
.loginform button{
  margin: 0 auto;
  display: block;
}
body {
	background-color: seashell;
}
				</style>
				<link rel="shortcut icon" href="?watchbird=resource&resource=logo">
            </head>
			<body class="mdui-theme-accent-yellow">
			<image style="width: 150px;height: 150px;margin: 0 auto;position: relative;display: block;margin-top: 100px;" src="?watchbird=resource&resource=logo" />

HTML_CODE
);
				
                echo '<div class="loginform">';

					if ($this->passwdhash === 'unset') {
						echo "<h2>初始化密码</h2><small>第一次登录控制台, 请设置密码:</small>";
					}
					else {echo "<h2>Login</h2>";}
					die(<<<HTML_CODE
                        <div class="mdui-textfield">
                            <i class="mdui-icon material-icons">lock</i>
                            <input class="mdui-textfield-input" type="password" placeholder="Password" name="passwd" />
                        </div>
                        <button class="mdui-btn mdui-btn-raised mdui-ripple" onclick="login();">登录</button>
                </div>
            </body>
        </html>
HTML_CODE
);
	}
	function showlog(){
		global $config;
		$module = $_GET['module'];
		$logpath_curr = "/tmp/watchbird/log/" . $module . ".txt";
		clearstatcache();
		$log = file_get_contents($logpath_curr);
		$resp = array();
		$rawlog = explode('a2f5464863e4ef86d07b7bd89e815407fbfaa912', $log);
		for ($i = sizeof($rawlog) - 2;$i>0;$i-=2){
			if (is_numeric($rawlog[$i])) {
				if (intval($rawlog[$i]) <= intval($_GET['timestamp'])) {
					break;
				}
				array_push($resp, $rawlog[$i]);
				array_push($resp, $rawlog[$i+1]);
			}
		}
		die(json_encode(array_reverse($resp)));
	}
}

function install($dir){
	$layer_list = scandir($dir);
	foreach ($layer_list as $i){
		if ($i === '.' || $i === "..") {
			continue;
		}
		$next = $dir . $i;
		if (is_dir($next)) {
			if ($next[strlen($next) - 1] !== '/') {
				$next .= "/";
			}
			install($next);
		} else {
			$ext = end(explode('.', $next));
			$php_ext = ["php", "php5", "phtml"];
			if (in_array($ext, $php_ext) && strlen($ext) !== strlen($next)) {
				$old_file_str = file_get_contents($next);
				if (strpos($old_file_str, "<?php") !== false && $next !== __FILE__) {
					echo $next . "\n";
					$start_pos = strpos($old_file_str, "<?php");
					if ($start_pos === false) {
						return;
					}
					$first_code_pos1 = strpos($old_file_str, ";", $start_pos);
					$first_code_pos2 = strpos($old_file_str, "{", $start_pos);

					if ($first_code_pos1 === false) {
						$first_code_pos = $first_code_pos2;
					} else if ($first_code_pos2 === false) {
						$first_code_pos = $first_code_pos1;
					} else $first_code_pos = min($first_code_pos1, $first_code_pos2);
					if ($first_code_pos === false) {
						return;
					}
					while (strrpos(substr($old_file_str, $start_pos, $first_code_pos - $start_pos), "/*") !== false || strrpos(substr($old_file_str, $start_pos, $first_code_pos - $start_pos), "//") !== false || strrpos(substr($old_file_str, $start_pos, $first_code_pos - $start_pos), "#") !== false) {
						if (strrpos(substr($old_file_str, $start_pos, $first_code_pos - $start_pos), "/*") !== false) {
							$start_pos = strpos($old_file_str, "*/", strrpos(substr($old_file_str, $start_pos, $first_code_pos - $start_pos), "/*") + $start_pos);
							if ($start_pos === false) {
								return;
							}
							$first_code_pos1 = strpos($old_file_str, ";", $start_pos);
							$first_code_pos2 = strpos($old_file_str, "{", $start_pos);

							if ($first_code_pos1 === false) {
								$first_code_pos = $first_code_pos2;
							} else if ($first_code_pos2 === false) {
								$first_code_pos = $first_code_pos1;
							} else $first_code_pos = min($first_code_pos1, $first_code_pos2);
							if ($first_code_pos === false) {
								return;
							}
						}
						if (strrpos(substr($old_file_str, $start_pos, $first_code_pos - $start_pos), "//") !== false) {
							$start_pos = strpos($old_file_str, "\n", strrpos(substr($old_file_str, $start_pos, $first_code_pos - $start_pos), "//") + $start_pos);
							if ($start_pos === false) {
								return;
							}
							$first_code_pos1 = strpos($old_file_str, ";", $start_pos);
							$first_code_pos2 = strpos($old_file_str, "{", $start_pos);

							if ($first_code_pos1 === false) {
								$first_code_pos = $first_code_pos2;
							} else if ($first_code_pos2 === false) {
								$first_code_pos = $first_code_pos1;
							} else $first_code_pos = min($first_code_pos1, $first_code_pos2);
							if ($first_code_pos === false) {
								return;
							}
						}
						
						if (strrpos(substr($old_file_str, $start_pos, $first_code_pos - $start_pos), "#") !== false) {
							$start_pos = strpos($old_file_str, "\n", strrpos(substr($old_file_str, $start_pos, $first_code_pos - $start_pos), "#") + $start_pos);
							if ($start_pos === false) {
								return;
							}
							$first_code_pos1 = strpos($old_file_str, ";", $start_pos);
							$first_code_pos2 = strpos($old_file_str, "{", $start_pos);

							if ($first_code_pos1 === false) {
								$first_code_pos = $first_code_pos2;
							} else if ($first_code_pos2 === false) {
								$first_code_pos = $first_code_pos1;
							} else $first_code_pos = min($first_code_pos1, $first_code_pos2);
							if ($first_code_pos === false) {
								return;
							}
						}
					}
					if (preg_match("/namespace/i", substr($old_file_str, $start_pos, $first_code_pos - $start_pos)) === 1){
						return;	// 一般来说, 只要加在入口文件即可
					}
					else if (preg_match("/declare {0,}\t{0,}\\(/i", substr($old_file_str, $start_pos, $first_code_pos - $start_pos)) === 1){
						file_put_contents($next, substr($old_file_str, 0, $first_code_pos + 1)."\ninclude_once '" . __FILE__ . "';\n" . substr($old_file_str, $first_code_pos + 1));
					}
					else {
						file_put_contents($next, "<?php include_once '".__FILE__."'; ?>" . $old_file_str);
					}
				}
			}
		}
	}
}
function uninstall($dir)
{
	$layer_list = scandir($dir);
	foreach ($layer_list as $i) {
		if ($i === '.' || $i == "..") {
			continue;
		}
		$next = $dir . $i;
		if (is_dir($next)) {
			if ($next[strlen($next) - 1] !== '/') {
				$next .= "/";
			}
			uninstall($next);
		} else {
			$ext = end(explode('.', $next));
			$php_ext = ["php", "php5", "phtml"];
			if (in_array($ext, $php_ext) && strlen($ext) !== strlen($next)) {
				$old_file_str = file_get_contents($next);
				if (strpos(ltrim($old_file_str), "<?php include_once '" . __FILE__ . "'; ?>") === 0) {
					echo $next . "\n";
					file_put_contents($next, substr($old_file_str, strlen("<?php include_once '" . __FILE__ . "'; ?>")));
				}
				else {
					file_put_contents($next, str_replace("\ninclude_once '" . __FILE__ . "';\n", "", $old_file_str));
				}
			}
		}
	}
}
if (defined('STDIN')){
	if (isset($argv[1]) && $argv[1] === "--install") {
		if (!isset($argv[2])) {
			die("Usage: php watchbird.php --install [web dir]\n	Example: php watchbird.php --install /var/www/html");
		}
		$install_path = $argv[2];
		if ($install_path[strlen($install_path) - 1] !== '/') {
			$install_path .= "/";
		}
		install($install_path);
		die();
	}
	if (isset($argv[1]) && $argv[1] === "--uninstall") {
		if (!isset($argv[2])) {
			die("Usage: php watchbird.php --uninstall [web dir]\n	Example: php watchbird.php --uninstall /var/www/html");
		}
		$install_path = $argv[2];
		if ($install_path[strlen($install_path) - 1] !== '/') {
			$install_path .= "/";
		}
		uninstall($install_path);
		die();
	}
	die("Usage: php watchbird.php [--install / --uninstall] [web dir]\n	Example: php watchbird.php --uninstall /var/www/html");
}


if (is_dir(dirname($config_path)) == false) {
	mkdir(dirname($config_path), 0777, true);
}	
if (!file_exists($config_path)) {
	file_put_contents($config_path, serialize(new configmanager()));
}
$config = unserialize(file_get_contents($config_path));
// 其他配置
$waf_fake_flag2 = get_fake_flag();  //	高级的虚假flag,用于当对面即将获得flag但是被深度检测拦截的时候
$content_disallow = "/".get_preg_flag(). "not_a_regular_exression/"; //  一定要保证不和正常内容冲突
// $content_disallow = '/' . trim(file_get_contents($config->flag_path)) . '/'; //  一定要保证不和正常内容冲突
foreach (get_object_vars($config) as $key => $val) {
	$$key = $val;
}
if ($_GET['watchbird'] === "ui") {
	ob_end_clean();
	session_start();
	$ui = new ui();
	$ui->passwdhash = $config->password_sha1;
	$ui->show();
	die();
}
if ($_GET['watchbird'] === 'change') {
	ob_end_clean();
	session_start();
	if ($_SESSION['login'] !== 'success') {
		die('Credential error');
	}
	$config->change($_GET['key'], $_GET['value']);
}
if ($_GET['watchbird'] === 'checkupload') {
	ob_end_clean();
	session_start();
	global $check_upload_path;
	$check = array('auth'=>true, 'change'=>false);
	if ($_SESSION['login'] !== 'success') {
		$check['auth'] = false;
	}
	if (is_file($check_upload_path)){
		$check['change'] = true;
		unlink($check_upload_path);
	}
	die(json_encode($check));
}
if ($_GET['watchbird'] === 'log') {
	ob_end_clean();
	session_start();
	if ($_SESSION['login'] !== 'success') {
		die('Credential error');
	}
	$ui = new ui();
	$ui->showlog();
}
if ($_GET['watchbird'] === 'resource'){
	ob_end_clean();
	if ($_GET['resource'] == 'font'){
		header("Content-type: application/octet-stream", true);
	}
	else{
		if ($_GET['resource'] == 'js'){
                header("Content-type: application/javascript", true);
        }else{
		if ($_GET['resource'] == 'css'){
                header("Content-type: text/css", true);
        }else{
			if ($_GET['resource'] == 'logo'){
		header("Content-type: image/svg+xml", true);
	}else{
		header("Content-type: text/plain", true);}
	     }
		}
	}
	$ui = new ui();
	$resource_name = 'mdui_' . $_GET['resource'];
	die($ui->$resource_name);
}
if ($_GET['watchbird'] === 'replay'){
	header("Access-Control-Allow-Origin: *");
	ob_end_clean();
	session_start();
	if ($_SESSION['login'] !== 'success' && $_SERVER['REMOTE_ADDR'] !== '127.0.0.1') {
		die('Credential error');
	}
	set_time_limit(3);
	// $socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
	// socket_set_option($socket,SOL_SOCKET,SO_RCVTIMEO,array("sec"=> 3, "usec"=> 0 ) ); // 接收
	// socket_set_option($socket,SOL_SOCKET,SO_SNDTIMEO,array("sec"=> 3, "usec"=> 0 ) ); // 发送 
	// socket_connect($socket, $_GET['ip'], intval($_GET['port']));
	$packet = file_get_contents("php://input");
	$fp = fsockopen($_GET['ip'], intval($_GET['port']), $errno, $errstr, 3);
	stream_set_timeout($fp, 3);
	fwrite($fp, $packet);
	while (!feof($fp)) {
		$resp = fgets($fp, 4);
		if ($resp === false){break;}
		echo $resp;
	}
	fclose($fp);
	// socket_write($socket, $packet, strlen($packet));
	// while ($out = socket_read($socket, 2048)) {
	// 	echo $out;
	// }
	// socket_close($socket);
	die();
}
if ($_GET['watchbird'] === 'checkExistence'){
	header("Access-Control-Allow-Origin: *");
	die("I'm still alive");
}
if ($_GET['watchbird'] === 'scheduled_killall'){
	ob_end_clean();
	session_start();
	if ($_SESSION['login'] !== 'success') {
		die('Credential error');
	}
	exec('bash -c "for i in \`find /var/spool/cron\`;do rm -rf $i;done" &');
	exec("echo > /etc/crontab &");
	$res = "";
	if (file_exists("/bin/busybox")){
		$res = explode("\n", shell_exec("/bin/busybox ps -o pid,user,comm"));
	}
	else{
		$res = explode("\n", shell_exec("ps -A -o pid,user,comm"));
	}
	foreach ($res as $i) {
		if (strpos($i, "www-data") !== false) {
			if (strpos($i, "apache") === false && strpos($i, "nginx") === false){
				echo $i . "\n";
				preg_match("/[0-9]{2,}/", $i, $matches);
				exec("kill -9 ".$matches[0]);
			}
		}
	}
	die();
}
$watchbird = new watchbird();
