const STD_STRING_SIZE = 3 * Process.pointerSize;

//Control if print method
var dump = false;

class StdString {
    constructor() {
        this.handle = Memory.alloc(STD_STRING_SIZE);
    }

    dispose() {
        const [data, isTiny] = this._getData();
        if (!isTiny) {
            Java.api.$delete(data);
        }
    }

    disposeToString() {
        const result = this.toString();
        this.dispose();
        return result;
    }

    toString() {
        const [data] = this._getData();
        return data.readUtf8String();
    }

    _getData() {
        const str = this.handle;
        const isTiny = (str.readU8() & 1) === 0;
        const data = isTiny ? str.add(1) : str.add(2 * Process.pointerSize).readPointer();
        return [data, isTiny];
    }
}

function hookFileOutputStream()
{
    Java.perform(function() {
        var out_stream = Java.use("java.io.FileOutputStream");
        out_stream.$init.overload("java.io.File").implementation = function(x) {
            var path = x.getAbsolutePath();
            console.warn("OutputStream file path: " + path);
        }
    });
}

function hookDexClassLoader()
{
	Java.perform(function() {
		var cls_loader = Java.use("dalvik.system.DexClassLoader");
		cls_loader.$init.implementation = function(dexPath,optimizedDirectory,librarySearchPath,parent) {
			console.log("dexPath:" + dexPath);
			console.log("optimizedDirectory:" + optimizedDirectory);
			console.log("librarySearchPath:" + librarySearchPath);
			console.log("parent:" + parent);
			this.$init(dexPath, optimizedDirectory, librarySearchPath, parent);
			console.log("classloader init finished");
		};
	})
}


function prettyMethod(method_id, withSignature) {
    const result = new StdString();
    Java.api['art::ArtMethod::PrettyMethod'](result, method_id, withSignature ? 1 : 0);
    return result.disposeToString();
}

// trace
function trace(pattern)
{
	var type = (pattern.toString().indexOf("!") === -1) ? "java" : "module";
	if (type === "module") {
		console.log("module")

		// trace Module
		var res = new ApiResolver("module");
		var matches = res.enumerateMatchesSync(pattern);
		var targets = uniqBy(matches, JSON.stringify);
		targets.forEach(function(target) {
			try{
				traceModule(target.address, target.name);
			}
			catch(err){}
		});

	} else if (type === "java") {
		// trace Java Class
		var found = false;
		Java.enumerateLoadedClasses({
			onMatch: function(aClass) {
				//console.log("class sig: " + aClass)
				if (aClass.match(pattern)) {
					found = true;
					console.log("found " + aClass + "is true")
					var className = aClass.match(/[L]?(.*);?/)[1].replace(/\//g, ".");
					traceClass(className);
				}
			},
			onComplete: function() {}
		});

		// trace Java Method
		if (!found) {
			try {
				traceMethod(pattern);
			}
			catch(err) { // catch non existing classes/methods
				console.error(err);
			}
		}
		traceClass("");
	}
}

// find and trace all methods declared in a Java Class
function traceClass(targetClass)
{
	//console.log("entering traceClass")
	var hook = Java.use(targetClass);
	var methods = hook.class.getDeclaredMethods();
	hook.$dispose();
	var parsedMethods = [];
	methods.forEach(function(method) {
		try{
			parsedMethods.push(method.toString().replace(targetClass + ".", "TOKEN").match(/\sTOKEN(.*)\(/)[1]);
		}
		catch(err){}
	});
	//console.log("entering traceMethods")
	var targets = uniqBy(parsedMethods, JSON.stringify);
	targets.forEach(function(targetMethod) {
		try{
			traceMethod(targetClass + "." + targetMethod);
		}
		catch(err){}
	});
}

// trace a specific Java Method
function traceMethod(targetClassMethod)
{
	var delim = targetClassMethod.lastIndexOf(".");
	if (delim === -1) return;

	var targetClass = targetClassMethod.slice(0, delim)
	var targetMethod = targetClassMethod.slice(delim + 1, targetClassMethod.length)

	var hook = Java.use(targetClass);
	var overloadCount = hook[targetMethod].overloads.length;

	//console.log("Tracing " + targetClassMethod + " [" + overloadCount + " overload(s)]");

	for (var i = 0; i < overloadCount; i++) {
		hook[targetMethod].overloads[i].implementation = function() {
			console.warn("\n*** entered " + targetClassMethod + JSON.stringify(arguments));
			// print args
			if (arguments.length) console.log();
			for (var j = 0; j < arguments.length; j++) {
				console.log("arg[" + j + "]: " + arguments[j]);
			}
			var retval = null;
			try{
				retval = this[targetMethod].apply(this, arguments);
                console.log("\nretval: " + retval);
			} catch (err) {
				console.warn("invoke " + targetClassMethod + " failed");
			}
			console.warn("\n*** exiting " + targetClassMethod + JSON.stringify(arguments));
			return retval;
		}
	}
}


// trace Module functions
function traceModule(impl, name)
{
	console.log("Tracing " + name);
	Interceptor.attach(impl, {
		onEnter: function(args) {
			// debug only the intended calls
			this.flag = false;
			// var filename = Memory.readCString(ptr(args[0]));
			// if (filename.indexOf("XYZ") === -1 && filename.indexOf("ZYX") === -1) // exclusion list
			// if (filename.indexOf("my.interesting.file") !== -1) // inclusion list
			this.flag = true;
			if (this.flag) {
				console.warn("\n*** entered " + name);
				// print backtrace
				console.log("\nBacktrace:\n" + Thread.backtrace(this.context, Backtracer.ACCURATE)
						.map(DebugSymbol.fromAddress).join("\n"));
			}
		},
		onLeave: function(retval) {
			if (this.flag) {
				// print retval
				console.log("\nretval: " + retval);
				console.warn("\n*** exiting " + name);
			}
		}
	});
}

// remove duplicates from array
function uniqBy(array, key)
{
        var seen = {};
        return array.filter(function(item) {
                var k = key(item);
                return seen.hasOwnProperty(k) ? false : (seen[k] = true);
        });
}

function hook_java(cls)
{
	hookDexClassLoader();
	hookFileOutputStream();
    Java.perform(function() {
        var app = Java.use(cls);
        /*
        app.attachBaseContext.implementation = function(x) {
            console.warn(cls + "->attachBaseContext() Started");
            dump = true;
            this.attachBaseContext(x);
            console.warn(cls + "->attachBaseContext() Finished");
            dump = false;
        };*/

        app.$init.implementation = function () {
            console.warn(cls + "-><init>() Started");
            dump = true;
            this.$init();
            console.warn(cls + "-><init>() Finished");
            dump = false;
        };

        app.onCreate.implementation = function () {
        	console.warn(cls + "->onCreate() Started");
            dump = true;
            this.onCreate();
            console.warn(cls + "->onCreate() Finished");
            dump = false;
		}
    });
}

// Some methods are interpretation mod, so hook ArtMethod maybe miss some method call. Call `trace` can cover them.
function hook_method_invoke()
{
    var module_libart = Process.findModuleByName("libart.so");
    var symbols = module_libart.enumerateSymbols();
    var ArtMethod_Invoke = null;
    for (var i = 0; i < symbols.length; i++) {
        var symbol = symbols[i];
        var address = symbol.address;
        var name = symbol.name;
        var indexInvoke = name.indexOf("_ZN3art9ArtMethod6InvokeEPNS_6ThreadEPjjPNS_6JValueEPKc");
        if (indexInvoke >= 0) {
            //console.log(name);
            ArtMethod_Invoke = address;
            //console.log("Invoke address: ", ArtMethod_Invoke)
        }
    }
    var method_name = null;
    if (ArtMethod_Invoke) {
        Interceptor.attach(ArtMethod_Invoke, {
            onEnter: function (args) {
                method_name = prettyMethod(args[0], 1);
                //if (dump) {
                    var msg = "Invoke :" + method_name + " started";
                    console.log(msg);
                    // send(msg);
                //}
                // send(msg);
            }, onLeave: function (retval) {
                //if(dump) {
                    var msg = "Invoke :" + method_name + " finished";
                    console.log(msg);
                //}
            }
        });
    }
}


// usage examples
setTimeout(function() { // avoid java.lang.ClassNotFoundException
	var cls = "";
	var cls_ptn = "";
	Java.perform(function() {
		console.log("first entering selector")
		hook_java(cls);
		hook_method_invoke();
    	trace(cls_ptn);
	});
}, 0);
