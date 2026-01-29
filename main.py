import base64
import random
import struct
import python_minifier

class OpCode:
    loadConst = 0x01
    loadGlobal = 0x04
    callFunc = 0x50
    execXor = 0x70
    halt = 0xFF

class Compiler:
    def __init__(self):
        self.constants = []
        self.bytecode = bytearray()
    
    def constant(self, value):
        if value in self.constants:
            return self.constants.index(value)
        
        self.constants.append(value)
        return len(self.constants) - 1
    
    def emit(self, opcode, operand=None):
        self.bytecode.append(opcode)
        
        if operand is not None:
            self.bytecode.extend(struct.pack(">I", operand))
    
    def compileXor(self, sourceCode, xorKey):
        self.constants = []
        self.bytecode = bytearray()
        
        encryptedBytes = bytearray()
        for byte in sourceCode.encode("utf-8"):
            encryptedBytes.append(byte ^ xorKey)
        
        codeIndex = self.constant(bytes(encryptedBytes))
        
        self.emit(OpCode.execXor, codeIndex)
        self.bytecode.extend(struct.pack(">I", xorKey))
        self.emit(OpCode.halt)
        
        return bytes(self.bytecode), self.constants, xorKey

def minify(sourceCode):
    return python_minifier.minify(
        sourceCode,
        rename_globals=True,
        rename_locals=True,
        remove_literal_statements=True,
        combine_imports=True,
        hoist_literals=True,
        remove_annotations=True,
        remove_pass=True,
        remove_debug=True,
    )

def encrypt(text, key):
    encrypted = bytearray()
    keyLength = len(key)
    
    for index, byte in enumerate(text.encode("utf-8")):
        encrypted.append(byte ^ ord(key[index % keyLength]))
    
    return base64.b64encode(encrypted).decode("utf-8")

def vmLoader(encryptedCode, encryptionKey):
    compiler = Compiler()
    
    encryptedBytes = base64.b64decode(encryptedCode)
    xorKey = sum(ord(c) for c in encryptionKey) % 256
    
    decryptedSource = bytearray()
    for index, byte in enumerate(encryptedBytes):
        decryptedSource.append(byte ^ ord(encryptionKey[index % len(encryptionKey)]))
    
    bytecode, constants, _ = compiler.compileXor(
        decryptedSource.decode("utf-8"),
        xorKey
    )
    
    vmSource = f"""
import struct as s
c={repr(constants)}
b={list(bytecode)}
class V:
 def __init__(q,x,y):q.s=[];q.c=y;q.b=bytes(x);q.p=0
 def r(q):b=q.b[q.p];q.p+=1;return b
 def i(q):d=q.b[q.p:q.p+4];q.p+=4;return s.unpack('>I',d)[0]
 def e(q):
  while q.p<len(q.b):
   o=q.r()
   if o=={OpCode.loadConst}:q.s.append(q.c[q.i()])
   elif o=={OpCode.loadGlobal}:n=q.c[q.i()];q.s.append(__builtins__.__dict__.get(n,None))
   elif o=={OpCode.callFunc}:a=q.i();x=[q.s.pop()for _ in range(a)];f=q.s.pop();q.s.append(f(*x[::-1]))
   elif o=={OpCode.execXor}:i=q.i();e=q.c[i];k=q.i();d=b''.join(bytes([b^(k&255)])for b in e);exec(d.decode('utf-8'),globals())
   elif o=={OpCode.halt}:break
  return q.s[-1]if q.s else None
V(b,c).e()
"""
    
    return minify(vmSource)

def loader(encryptedCode, encryptionKey): 
    return f"exec(''.join(chr(ord(d)^ord('{encryptionKey}'[i%len('{encryptionKey}')])) for i,d in enumerate('{encryptedCode}')))"

def script(inputPath, encryptionKey):
    with open(inputPath, "r") as file:
        sourceCode = file.read()
    
    minifiedCode = minify(sourceCode)
    encryptedCode = encrypt(minifiedCode, encryptionKey)
    output = vmLoader(encryptedCode, encryptionKey)
    
    print("Saved script to vm.py")
    
    with open("vm.py", "w") as file:
        file.write(output)

path = input("Enter path to script: ")
key = str(random.randint(1, 100))
script(path, key)
input("Press Enter to exit . . .")
