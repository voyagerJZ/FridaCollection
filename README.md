# FridaCollection
记录用到的Frida脚本。

## Firda Usage

### Register Message Handler

```
#python code
def my_message_handler(message , payload): #define our handler
	print message
	print payload
...
script.on("message" , my_message_handler) #register our handler to be called
script.load()
```

### Hook Method
* No overload method
```
var my_class = Java.use("<class name>")
my_class.<func_name>.implementation = function(<params>) {
}
```
* Has overload method
```
my_class.fun.overload("int" , "int").implementation = function(x,y){ }
my_class.fun.overload("java.lang.String").implementation = function(x){ }
```

### Use Exist Class Instance
* Java.choose("<class name>") -> Find all exist class instances
```
Java.choose("<cls name>", {
    onMatch: function (instance) {
        console.log("Found instance: " + instance);
        console.log("Result of secret func: " + instance.secret());
    },
    onComplete: function () { }
});
```


### Hook Native Function
#### Hook Export Function
```
var str_name_so = "libnative-lib.so";    
var str_name_func = "func_exp";          
//var str_name_func = "_Z12func_exp_cppv";   

var so_base = Module.findBaseAddress(str_name_so)
var n_addr_func = Module.findExportByName(str_name_so , str_name_func);
console.log("func addr is ---" + n_addr_func);

Interceptor.attach(n_addr_func, {
    //在hook函数之前执行的语句
    onEnter: function(args) 
    {
        console.log("hook on enter")
    },
    //在hook函数之后执行的语句
    onLeave:function(retval)
    {
        console.log("hook on leave")
    }
});
        
```


#### Hook Unexport Function

```
var str_name_so = "libnative-lib.so";    
var n_addr_func_offset = 0x7078;         

//加载到内存后 函数地址 = so地址 + 函数偏移
var n_addr_so = Module.findBaseAddress(str_name_so);
var n_addr_func = parseInt(n_addr_so, 16) + n_addr_func_offset;

var ptr_func = new NativePointer(n_addr_func);
Interceptor.attach(ptr_func, 
{
    onEnter: function(args) 
    {
        console.log("hook on enter no exp");
    },
    onLeave:function(retval)
    {
        console.log("hook on Leave no exp");
    }
});
```

### Read Memory
```
var flag_addr = parseInt(so_base, 16)+flag_offset; 
var flag_ptr = new NativePointer(flag_addr);      // 转换为nativepointer
Interceptor.attach(security_check,{
    onEnter: function(args){    // jni函数进入时
        console.log("---- enter ----");
        var flag0 = flag_ptr.readByteArray(0x20); 
        console.log(hexdump(flag0,{
            offset: 0,
            length: 0x20,
            header: true,
            ansi: false
        }))
        console.log("---- enter end ----");
    },
    onLeave: function(retval){  // jni函数返回时
        var flag = flag_ptr.readByteArray(0x20);  //打印内存中的值

        console.log("---- leave ----");
        console.log(hexdump(flag,{
            offset: 0,
            length: 0x20,
            header: true,
            ansi: false
        }));
        console.log("---- leave end ----");
    }
});
```

## Frida 主动调用方法

* 这里获取对象的方法有两个
    * 直接获取内存中已经有的对象
    * 自己 创建（new）一个

### Frida invoke static java method
```
public static String enc(String str_data, int n_conunt)

function call_enc(str_data, n_cnt) 
{
 //这里写函数对应的类名
  var str_cls_name = "com.wangtietou.test_rpc_all.Test_Enc_Dec";
  //返回值 
  var str_ret = null;

  Java.perform(function () 
  {
    //打log方便调试
    console.log("===========>on enc");  

    // 获取类
    var obj = Java.use(str_cls_name);

    //调用类方法 因为这里是静态方法 所以可以直接调用
    str_ret = obj.enc(str_data, n_cnt);
    
    //打印结果 方便调试
    console.log("enc result: " + str_ret);
  });
  return str_ret;
}
```

### Frida invoke static native method
```
public static native String c_enc(String str_data)

function call_c_enc(str_data) 
{
 //这里写函数对应的类名
  var str_cls_name = "com.wangtietou.test_rpc_all.Test_Enc_Dec";
  //返回值 
  var str_ret = null;

  Java.perform(function () 
  {
    //打log方便调试
    console.log("===========>on enc");  

    // 获取类
    var obj = Java.use(str_cls_name);

    //调用类方法 因为这里是静态方法 所以可以直接调用
    str_ret = obj.c_enc(str_data);
    
    //打印结果 方便调试
    console.log("enc result: " + str_ret);
  });
  return str_ret;
}
```
### Frida invoke java method && Frida invoke native method
```
public  String enc(String str_data)

//1. instance.方法名（参数，...）  //直接获取已有对象
//从内存中（堆）直接搜索已存在的对象
Java.choose('xxx.xxx.xxx '， //这里写类名 
{
    //onMatch 匹配到对象执行的回调函数
    onMatch: function (instance) 
    {
    },
    //堆中搜索完成后执行的回调函数
    onComplete: function () 
    {
    }
});

function call_enc(str_data) 
{
 //这里写函数对应的类名
  var str_cls_name = "com.wangtietou.test_rpc_all.Test_Enc_Dec";
  //返回值 
  var str_ret = null;
  
  Java.perform(function () 
  {
      Java.choose(str_cls_name, 
      {
        onMatch: function (instance) 
        {
            //调试用
            console.log("onMatch ");  
            //直接调用对象的函数 instance是找到的对象
            str_ret = instance.enc(str_data);
        },
        onComplete: function () 
        {
        }
      });
  });
  console.log("enc result: " + str_ret);
  return str_ret;
}


//2. 类名引用.方法名（参数，...） //新创建的对象
 //获取类的引用
var cls = Java.use('这里写类名');

//调用构造函数 创建新对象  这里注意参数
var obj = cls.$new(args,...);

function call_enc(str_data) 
{
 //这里写函数对应的类名
  var str_cls_name = "com.wangtietou.test_rpc_all.Test_Enc_Dec";
  //返回值 
  var str_ret = null;
  
  Java.perform(function () 
  {
       //获取类的引用
       var cls = Java.use(str_cls_name);

       //调用构造函数 创建新对象  这里注意参数
       var obj = cls.$new();
      
       //调用新对象的对象方法 enc
       str_ret = obj.enc(str_data)；
  });
  console.log("enc result: " + str_ret);
  return str_ret;
}

```

### Frida invoke so method

Frida API: NativeFunction(address, returnType, argTypes[, abi])

Frida 支持类型
* void
* pointer
* int 
* uint
* long
* ulong 
* char
* uchar
* size_t
* ssize_t
* float
* double
* int8
* uint8
* int16
* uint16
* int32
* uint32
* int64
* uint64
* bool

```
c++: char* c_enc_2(char* p_str_data,  int n_num)


function test_c(str_data, n_num) 
{
    var str_name_so = "libnative-lib.so";    //要hook的so名
    var str_name_func = "c_enc_2";          //要hook的函数名
    
    //获取函数的地址
    var n_addr_func = Module.findExportByName(str_name_so , str_name_func);
    console.log("func addr is ---" + n_addr_func);

    //定义NativeFunction 等下要调用
    var func_c_enc = new NativeFunction(n_addr_func , 'pointer', ['pointer', 'int']);
    
    //调用frida的api申请空间 填入字符串 模拟char*
    var str_data_arg = Memory.allocUtf8String(str_data);
    
     //调用so层的c函数
    var p_str_ret = func_c_enc(str_data_arg, n_num);
    
    //读取字符串  
    var str_ret = Memory.readCString(p_str_ret);
    return str_ret;
}
```
