<?php

/**
 * https://github.com/Gregwar/Captcha
 * Thank the author! I only minified the script to half the file size. Tool used: https://wtools.io/php-minifier
**/

//CaptchaBuilderInterface
namespace Gregwar\Captcha;interface CaptchaBuilderInterface{public function build($width,$height,$font,$fingerprint);public function save($filename,$quality);public function get($quality);public function output($quality);}
//PhraseBuilderInterface
namespace Gregwar\Captcha;interface PhraseBuilderInterface{public function build();public function niceize($str);}
//ImageFileHandler
namespace Gregwar\Captcha;use Symfony\Component\Finder\Finder;class ImageFileHandler{protected $imageFolder;protected $webPath;protected $gcFreq;protected $expiration;public function __construct($imageFolder,$webPath,$gcFreq,$expiration){$this->imageFolder=$imageFolder;$this->webPath=$webPath;$this->gcFreq=$gcFreq;$this->expiration=$expiration;}
public function saveAsFile($contents){$this->createFolderIfMissing();$filename=md5(uniqid()).'.jpg';$filePath=$this->webPath.'/'.$this->imageFolder.'/'.$filename;imagejpeg($contents,$filePath,15);return'/'.$this->imageFolder.'/'.$filename;}
public function collectGarbage(){if(!mt_rand(1,$this->gcFreq)==1){return false;}
$this->createFolderIfMissing();$finder=new Finder();$criteria=sprintf('<= now - %s minutes',$this->expiration);$finder->in($this->webPath.'/'.$this->imageFolder)
->date($criteria);foreach($finder->files()as $file){unlink($file->getPathname());}
return true;}
protected function createFolderIfMissing(){if(!file_exists($this->webPath.'/'.$this->imageFolder)){mkdir($this->webPath.'/'.$this->imageFolder,0755);}}}
//PhraseBuilder
namespace Gregwar\Captcha;class PhraseBuilder implements PhraseBuilderInterface{public $length;public $charset;public function __construct($length=5,$charset='abcdefghijklmnpqrstuvwxyz123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'){$this->length=$length;$this->charset=$charset;}
public function build($length=null,$charset=null){if($length!==null){$this->length=$length;}
if($charset!==null){$this->charset=$charset;}
$phrase='';$chars=str_split($this->charset);for($i=0;$i<$this->length;$i++){$phrase.=$chars[array_rand($chars)];}
return $phrase;}
public function niceize($str){return self::doNiceize($str);}
public static function doNiceize($str){return strtr(strtolower($str),'01','ol');}
public static function comparePhrases($str1,$str2){return self::doNiceize($str1)===self::doNiceize($str2);}}
//CaptchaBuilder
namespace Gregwar\Captcha;use \Exception;class CaptchaBuilder implements CaptchaBuilderInterface{protected $fingerprint=array();protected $useFingerprint=false;protected $textColor=array();protected $lineColor=null;protected $backgroundColor=null;protected $backgroundImages=array();protected $contents=null;protected $phrase=null;protected $builder;protected $distortion=true;protected $maxFrontLines=null;protected $maxBehindLines=null;protected $maxAngle=8;protected $maxOffset=5;protected $interpolation=true;protected $ignoreAllEffects=false;protected $allowedBackgroundImageTypes=array('image/png','image/jpeg','image/gif');public function getContents(){return $this->contents;}
public function setInterpolation($interpolate=true){$this->interpolation=$interpolate;return $this;}
public $tempDir='temp/';public function __construct($phrase=null,PhraseBuilderInterface $builder=null){if($builder===null){$this->builder=new PhraseBuilder;}else{$this->builder=$builder;}
$this->phrase=is_string($phrase)?$phrase:$this->builder->build($phrase);}
public function setPhrase($phrase){$this->phrase=(string)$phrase;}
public function setDistortion($distortion){$this->distortion=(bool)$distortion;return $this;}
public function setMaxBehindLines($maxBehindLines){$this->maxBehindLines=$maxBehindLines;return $this;}
public function setMaxFrontLines($maxFrontLines){$this->maxFrontLines=$maxFrontLines;return $this;}
public function setMaxAngle($maxAngle){$this->maxAngle=$maxAngle;return $this;}
public function setMaxOffset($maxOffset){$this->maxOffset=$maxOffset;return $this;}
public function getPhrase(){return $this->phrase;}
public function testPhrase($phrase){return($this->builder->niceize($phrase)==$this->builder->niceize($this->getPhrase()));}
public static function create($phrase=null){return new self($phrase);}
public function setTextColor($r,$g,$b){$this->textColor=array($r,$g,$b);return $this;}
public function setBackgroundColor($r,$g,$b){$this->backgroundColor=array($r,$g,$b);return $this;}
public function setLineColor($r,$g,$b){$this->lineColor=array($r,$g,$b);return $this;}
public function setIgnoreAllEffects($ignoreAllEffects){$this->ignoreAllEffects=$ignoreAllEffects;return $this;}
public function setBackgroundImages(array $backgroundImages){$this->backgroundImages=$backgroundImages;return $this;}
protected function drawLine($image,$width,$height,$tcol=null){if($this->lineColor===null){$red=$this->rand(100,255);$green=$this->rand(100,255);$blue=$this->rand(100,255);}else{$red=$this->lineColor[0];$green=$this->lineColor[1];$blue=$this->lineColor[2];}
if($tcol===null){$tcol=imagecolorallocate($image,$red,$green,$blue);}
if($this->rand(0,1)){$Xa=$this->rand(0,$width/2);$Ya=$this->rand(0,$height);$Xb=$this->rand($width/2,$width);$Yb=$this->rand(0,$height);}else{$Xa=$this->rand(0,$width);$Ya=$this->rand(0,$height/2);$Xb=$this->rand(0,$width);$Yb=$this->rand($height/2,$height);}
imagesetthickness($image,$this->rand(1,3));imageline($image,$Xa,$Ya,$Xb,$Yb,$tcol);}
protected function postEffect($image){if(!function_exists('imagefilter')){return;}
if($this->backgroundColor!=null||$this->textColor!=null){return;}
if($this->rand(0,1)==0){imagefilter($image,IMG_FILTER_NEGATE);}
if($this->rand(0,10)==0){imagefilter($image,IMG_FILTER_EDGEDETECT);}
imagefilter($image,IMG_FILTER_CONTRAST,$this->rand(-50,10));if($this->rand(0,5)==0){imagefilter($image,IMG_FILTER_COLORIZE,$this->rand(-80,50),$this->rand(-80,50),$this->rand(-80,50));}}
protected function writePhrase($image,$phrase,$font,$width,$height){$length=mb_strlen($phrase);if($length===0){return\imagecolorallocate($image,0,0,0);}
$size=(int)round($width / $length)-$this->rand(0,3)-1;$box=\imagettfbbox($size,0,$font,$phrase);$textWidth=$box[2]-$box[0];$textHeight=$box[1]-$box[7];$x=(int)round(($width-$textWidth)/ 2);$y=(int)round(($height-$textHeight)/ 2)+$size;if(!$this->textColor){$textColor=array($this->rand(0,150),$this->rand(0,150),$this->rand(0,150));}else{$textColor=$this->textColor;}
$col=\imagecolorallocate($image,$textColor[0],$textColor[1],$textColor[2]);for($i=0;$i<$length;$i++){$symbol=mb_substr($phrase,$i,1);$box=\imagettfbbox($size,0,$font,$symbol);$w=$box[2]-$box[0];$angle=$this->rand(-$this->maxAngle,$this->maxAngle);$offset=$this->rand(-$this->maxOffset,$this->maxOffset);\imagettftext($image,$size,$angle,$x,$y+$offset,$col,$font,$symbol);$x+=$w;}
return $col;}
public function isOCRReadable(){if(!is_dir($this->tempDir)){@mkdir($this->tempDir,0755,true);}
$tempj=$this->tempDir.uniqid('captcha',true).'.jpg';$tempp=$this->tempDir.uniqid('captcha',true).'.pgm';$this->save($tempj);shell_exec("convert $tempj $tempp");$value=trim(strtolower(shell_exec("ocrad $tempp")));@unlink($tempj);@unlink($tempp);return $this->testPhrase($value);}
public function buildAgainstOCR($width=150,$height=40,$font=null,$fingerprint=null){do{$this->build($width,$height,$font,$fingerprint);}while($this->isOCRReadable());}
public function build($width=150,$height=40,$font=null,$fingerprint=null){if(null!==$fingerprint){$this->fingerprint=$fingerprint;$this->useFingerprint=true;}else{$this->fingerprint=array();$this->useFingerprint=false;}
if($font===null){$font=__DIR__.'/Font/captcha'.$this->rand(0,5).'.ttf';}
if(empty($this->backgroundImages)){$image=imagecreatetruecolor($width,$height);if($this->backgroundColor==null){$bg=imagecolorallocate($image,$this->rand(200,255),$this->rand(200,255),$this->rand(200,255));}else{$color=$this->backgroundColor;$bg=imagecolorallocate($image,$color[0],$color[1],$color[2]);}
imagefill($image,0,0,$bg);}else{$randomBackgroundImage=$this->backgroundImages[rand(0,count($this->backgroundImages)-1)];$imageType=$this->validateBackgroundImage($randomBackgroundImage);$image=$this->createBackgroundImageFromType($randomBackgroundImage,$imageType);}
if(!$this->ignoreAllEffects){$square=$width*$height;$effects=$this->rand($square/3000,$square/2000);if($this->maxBehindLines!=null&&$this->maxBehindLines>0){$effects=min($this->maxBehindLines,$effects);}
if($this->maxBehindLines!==0){for($e=0;$e<$effects;$e++){$this->drawLine($image,$width,$height);}}}
$color=$this->writePhrase($image,$this->phrase,$font,$width,$height);if(!$this->ignoreAllEffects){$square=$width*$height;$effects=$this->rand($square/3000,$square/2000);if($this->maxFrontLines!=null&&$this->maxFrontLines>0){$effects=min($this->maxFrontLines,$effects);}
if($this->maxFrontLines!==0){for($e=0;$e<$effects;$e++){$this->drawLine($image,$width,$height,$color);}}}
if($this->distortion&&!$this->ignoreAllEffects){$image=$this->distort($image,$width,$height,$bg);}
if(!$this->ignoreAllEffects){$this->postEffect($image);}
$this->contents=$image;return $this;}
public function distort($image,$width,$height,$bg){$contents=imagecreatetruecolor($width,$height);$X=$this->rand(0,$width);$Y=$this->rand(0,$height);$phase=$this->rand(0,10);$scale=1.1+$this->rand(0,10000)/ 30000;for($x=0;$x<$width;$x++){for($y=0;$y<$height;$y++){$Vx=$x-$X;$Vy=$y-$Y;$Vn=sqrt($Vx*$Vx+$Vy*$Vy);if($Vn!=0){$Vn2=$Vn+4*sin($Vn / 30);$nX=$X+($Vx*$Vn2 / $Vn);$nY=$Y+($Vy*$Vn2 / $Vn);}else{$nX=$X;$nY=$Y;}
$nY=$nY+$scale*sin($phase+$nX*0.2);if($this->interpolation){$p=$this->interpolate($nX-floor($nX),$nY-floor($nY),$this->getCol($image,floor($nX),floor($nY),$bg),$this->getCol($image,ceil($nX),floor($nY),$bg),$this->getCol($image,floor($nX),ceil($nY),$bg),$this->getCol($image,ceil($nX),ceil($nY),$bg));}else{$p=$this->getCol($image,round($nX),round($nY),$bg);}
if($p==0){$p=$bg;}
imagesetpixel($contents,$x,$y,$p);}}
return $contents;}
public function save($filename,$quality=90){imagejpeg($this->contents,$filename,$quality);}
public function getGd(){return $this->contents;}
public function get($quality=90){ob_start();$this->output($quality);return ob_get_clean();}
public function inline($quality=90){return'data:image/jpeg;base64,'.base64_encode($this->get($quality));}
public function output($quality=90){imagejpeg($this->contents,null,$quality);}
public function getFingerprint(){return $this->fingerprint;}
protected function rand($min,$max){if(!is_array($this->fingerprint)){$this->fingerprint=array();}
if($this->useFingerprint){$value=current($this->fingerprint);next($this->fingerprint);}else{$value=mt_rand((int)$min,(int)$max);$this->fingerprint[]=$value;}
return $value;}
protected function interpolate($x,$y,$nw,$ne,$sw,$se){list($r0,$g0,$b0)=$this->getRGB($nw);list($r1,$g1,$b1)=$this->getRGB($ne);list($r2,$g2,$b2)=$this->getRGB($sw);list($r3,$g3,$b3)=$this->getRGB($se);$cx=1.0-$x;$cy=1.0-$y;$m0=$cx*$r0+$x*$r1;$m1=$cx*$r2+$x*$r3;$r=(int)($cy*$m0+$y*$m1);$m0=$cx*$g0+$x*$g1;$m1=$cx*$g2+$x*$g3;$g=(int)($cy*$m0+$y*$m1);$m0=$cx*$b0+$x*$b1;$m1=$cx*$b2+$x*$b3;$b=(int)($cy*$m0+$y*$m1);return($r<<16)|($g<<8)|$b;}
protected function getCol($image,$x,$y,$background){$L=imagesx($image);$H=imagesy($image);if($x<0||$x>=$L||$y<0||$y>=$H){return $background;}
return imagecolorat($image,$x,$y);}
protected function getRGB($col){return array((int)($col>>16)&0xff,(int)($col>>8)&0xff,(int)($col)&0xff,);}
protected function validateBackgroundImage($backgroundImage){if(!file_exists($backgroundImage)){$backgroundImageExploded=explode('/',$backgroundImage);$imageFileName=count($backgroundImageExploded)>1?$backgroundImageExploded[count($backgroundImageExploded)-1]:$backgroundImage;throw new Exception('Invalid background image: '.$imageFileName);}
$finfo=finfo_open(FILEINFO_MIME_TYPE);$imageType=finfo_file($finfo,$backgroundImage);finfo_close($finfo);if(!in_array($imageType,$this->allowedBackgroundImageTypes)){throw new Exception('Invalid background image type! Allowed types are: '.join(', ',$this->allowedBackgroundImageTypes));}
return $imageType;}
protected function createBackgroundImageFromType($backgroundImage,$imageType){switch($imageType){case'image/jpeg':$image=imagecreatefromjpeg($backgroundImage);break;case'image/png':$image=imagecreatefrompng($backgroundImage);break;case'image/gif':$image=imagecreatefromgif($backgroundImage);break;default:throw new Exception('Not supported file type for background image!');}
return $image;}}
