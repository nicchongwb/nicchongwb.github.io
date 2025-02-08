+++
date = '2024-07-11T15:56:35+08:00'
draft = false
title = 'Compile-time Security Controls: Bridging the Gap Beyond SAST'
+++

**Disclaimer:**
*I am not a compiler expert. This article goal is to express the possibility of how we can look compile-time security controls for Application Security.*

# What is SAST

Static Application Security Testing (SAST) involves the scanning of static application code before it is compiled. Many organizations rely on SAST to identify vulnerabilities in the initial stages of development. This article will explore the limitations of SAST and how we can fill these gaps with compile-time security controls. The article uses the Java programming language to demonstrate how compile-time security controls are applied to Java programs. However, the strategy can be applied to other compiled programming languages like C++, Go, Rust, etc. 

# The limitations of SAST

A typical Secure Software Development Lifecycle (SSDLC) involves SAST and DAST (Dynamic Application Security Testing) for security assurance. One of the goals of SAST is to detect insecure code patterns by scanning the static code. SAST tools usually allow engineers to write rules for scanning, data flow analysis, or taint tracking. Assuming we know all the methods' names that if used insecurely, will lead to common application vulnerabilities like SQL Injection, Deserialization, etc and write SAST rules to detect them. 

Does this guarantee that our application code meets our security requirements before it is built?

No, SAST scans (as of the time of writing) only work with static sources like application source code. That means that the scan only sees as far as what it parses but it doesn’t have complete knowledge of the fully resolved Abstract Syntax Tree (AST).


![Fig 1. Overview of SAST tool & Compile-time Security Control.](figure-1.png)

Let’s see an example of how SAST is not able to detect usage of dangerous methods. The code below is one of our application codes to be scanned by SAST. We see that a third-party library Deserializagator is used to deserialize our serializedData into a MyCustomClass class.

```Java
import com.deserailizagator.deserializer.Deserializagator;

public class Main {
    public static void main(String[] args){
        byte[] serializedData = getUserInput();
        MyCustomClass deserializedObject = Deserializagator.deserialize(serializedData, YourCustomClass.class);
    }
}
```

The SAST tool will scan the code above without compiling it. The issue with this is that we don’t know if the implementation of `Deserializagator.deserialize()` is safe or not. Of course, one may argue that the third-party library can be audited and if unsafe, a SAST rule can be written. However, to account for all third-party libraries that may potentially provide APIs that have unsafe implementation may not be a viable solution.

Let’s take a look at `Deserializagator.deserialize()` implementation.

```Java
package com.deserailizagator.deserializer;

public class Deserializagator {
    public static <T> T deserialize(byte[] input, Class<T> clazz) {
        T deserializedObject = null;
        ByteArrayInputStream bais = new ByteArrayInputStream(input);
        ObjectInputStream ois = new ObjectInputStream(bais);  
        deserializedObject = clazz.cast(ois.readObject());
            
        ois.close();
        bais.close();
        return deserializedObject;
    }
}
```

Readers with Java security source code review can immediately tell that the `deserialize()` method is vulnerable to Java deserialization attacks. For more information on Java deserialization attacks, take a look at [OWASP Cheatsheet - Deserialization](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html#whitebox-review_2).

In the case of Java programs, a build tool like Gradle or Maven is typically used for dependency resolution before the Java compiler compiles the program. The dependency resolution is responsible for locating and downloading third-party dependencies.

The limitation of SAST tools is that it only scans code and not compile/build them. This means that SAST tools will not have complete knowledge of the fully resolved Abstract Syntax Tree (AST) generated during compilation.

## Compile-time Security Controls

We usually think of memory safety checks when we see compile-time security checks. However, we can extend compiler behaviors to check for potential runtime vulnerabilities like Insecure Deserialization, SQL Injections, etc. By performing these checks at the compilation layer, we can detect and handle such potential vulnerabilities before they manifest at runtimes.

The approach in modeling our detection and handling strategy consists of the following:
1. Identify the root factors that contributes to the vulnerability
2. Determine actions of security control

The following are the requirements for compile-time security controls:
- Compiler able to be extended to custom compiler process
- Programming language able to support processing of metadata such as tags, annotations, etc.

Lets model our detection and handling strategy from the Java code previously mentioned.

Our application code:
```Java
import com.deserailizagator.deserializer.Deserializagator;

public class Main {
    public static void main(String[] args){
        byte[] serializedData = getUserInput();
        MyCustomClass deserializedObject = Deserializagator.deserialize(serializedData, YourCustomClass.class);	
    }
}
```

Third-party library code:
```Java
package com.deserailizagator.deserializer;

public class Deserializagator {
    public static <T> T deserialize(byte[] input, Class<T> clazz) {
        T deserializedObject = null;
            
        ByteArrayInputStream bais = new ByteArrayInputStream(input);
        ObjectInputStream ois = new ObjectInputStream(bais);    
        deserializedObject = clazz.cast(ois.readObject());
            
        ois.close();
        bais.close();
        return deserializedObject;
    }
}
```

The vulnerability in scope is Insecure Deserialization. Java provides the native APIs ByteArrayInputStream and ObjectInputStream for deserialization. The issue with the `deserialize()` method is that there is no validation for the input byte array. Of course a potential patch will be adding a validation step to validate the input before streaming the bytes to an ObjectInputStream.

![Fig 2. Implementation flow of deserialization method.](figure-2.png)

We can implement a Java compiler plugin that traverses the Java AST and programmatically detect if an non-validated byte array is used for ByteArrayInputStream and ObjectInputStream. From there we can log compilation errors and fail the build.

## Approaching Compile-time Security Controls

From the previous example, we can implement a compile-time security control to explicitly detect the sequential invocation of a series of dangerous APIs/methods. However, such a naive approach only accounts for 1 specific sequence of dangerous APIs/methods. 

Instead, we should consider that there are many ways that these such APIs/methods can be used and lead to a potential vulnerability like Insecure Deserialization. This adds to the complexity of the compile-time security control since it leverages on how the structure of the AST, and the structure of the AST is heavily determined by the code implementation.

Consider our security control specifically checking for the following sequence of methods invoked.

![Fig 3. Explicit check for methods chain](figure-3.png)

What about other sequences of methods invoked that will still lead to the same vulnerability?


![Fig 4. Alternate method chain](/static/images/blog/ctscbtgbs/figure-4.png)

If our security control is tightly coupled to the sequence of methods invoked, then it is only limited to that case. This approach is not viable for implementing the control.

There are 2 simpler approach to implement compile-time security control:
1. Detecting Fully qualified name with method signature
2. Metadata processing of known insecure methods

### Detecting Fully Qualified Method Name and Signature

A simple but naive approach is to traverse the AST and detect for dangerous fully qualified names (package and classpath inclusive) of a method with its signature. With this approach, we don’t consider the sequence of methods called, as we only care if a specific method is present in the AST. However, there are drawbacks to this approach. We lack context of whether the method is used securely or not because some methods are only dangerous when used in conjunction with other methods.

## Metadata processing of known insecure methods

The second approach is to leverage on the language metadata processing capabilities. In the case of Java, we can leverage Java annotations. If the method is known to be unsafe or can be used unsafely, the method can be annotated with an annotation to denote as such.

```Java
package com.deserailizagator.deserializer;

@Retention(RUNTIME)
@Target(METHOD)
public @interface Unsafe {}

@Retention(RUNTIME)
@Target({METHOD, CONSTRUCTOR, TYPE})
public @interface Allow {
    @Retention(RUNTIME)
    @Target(METHOD)
    @interface Unsafe
}

public class Deserializagator {
    @Usafe
    public static <T> T deserialize(byte[] input, Class<T> clazz) {
        T deserializedObject = null;
            
        ByteArrayInputStream bais = new ByteArrayInputStream(input);
        ObjectInputStream ois = new ObjectInputStream(bais);    
        deserializedObject = clazz.cast(ois.readObject());
            
        ois.close();
        bais.close();
        return deserializedObject;
    }
}
```

The code above is the same `deserialize()` method but this time annotated with the `@Unsafe` annotation. Also note that there is another annotation `@Allow.Unsafe` which is used for the compile-time security control to relax the control.

Now when we use deserialize in our application, the compile-time security control will be able to detect that deserialize has the `@Unsafe` annotation. However, we can also annotate the immediate parent scope of where deserialize is called with `@Allow.Unsafe` to relax the control.


```Java
import com.deserailizagator.deserializer.Deserializagator;
import com.deserailizagator.deserializer.Deserializagator.Allow;

public class Main {
    @Allow.Unsafe
    public static void main(String[] args){
        byte[] serializedData = getUserInput();
        MyCustomClass deserializedObject = Deserializagator.deserialize(serializedData, YourCustomClass.class);	
    }
}
```

Below is an example of how the control can traverse the AST and perform its operation on whether to fail to build or not.

![Fig 5. Compile-time security control for build](/static/images/blog/ctscbtgbs/figure-5.png)


Using this approach requires the developers to explicitly annotate unsafe methods. This approach complements SAST tools as we can just detect for annotations like `@Allow.Unsafe` in the source code, and contribute to other security efforts like application security risk scoring, or visibility of where unsafe APIs/methods are used. Other teams like product security can leverage this to look out for low hanging fruits during secure code reviews.

With all that said, having a feature like Java annotations in a compiled programming language can be very useful for implementing compile-time security controls. Programming Language developers should consider this as a First Class feature and also provide Compiler APIs for other developers to extend the compilation process if they already have not done so.

# Disadvantages of Compile-time Security Controls

The most obvious disadvantage is to maintain compile-time security controls for every techstack. This is because such controls interface with the compilation layer of the targeted techstack. Almost every technology in the stack has their own unique compilation system. Take for example JVM languages such as Java and Kotlin. There are libraries that can work on both Java and Kotlin (JVM). You will need to implement compile-time security controls for each Java and Kotlin (JVM) because they have different compilers.

Extending the compilation process for such security controls will likely involve some level of technical understanding of the compiler itself. Also, some compilers may not provide stable compiler APIs to allow developers to extend the compilation process. These compiler APIs are prone to changes or may not even be well maintained as they are usually not the main priority of programming language developers. This will hinder engineering efforts in developing such controls. Hence, implementing these controls may require a considerable amount of time and effort.

The next disadvantage is that compile-time security controls may produce unexpected results during compilation time. These controls may produce unwanted side-effects on the application compilation time. This is especially true if the control is modifying the AST before the bytecode/executable code is produced.

# Closing Remarks

In conclusion, compile-time security controls can help bridge the gap beyond SAST as it checks and provides assurance at the compilation layer. These controls open the door to a broader security landscape, allowing for the development of application security risk scoring mechanisms and enhancing the visibility of where potentially unsafe APIs/methods are employed within your codebase.

It not only strengthens the security of your software but also empowers product security teams to identify low-hanging security issues during rigorous code reviews, further fortifying your application's defense.

While implementing such controls may seem like it requires a substantial research and engineering effort, it is worth to consider to apply this strategy to your application security program.

