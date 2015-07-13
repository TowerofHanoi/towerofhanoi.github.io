---
title:      PoliCTF 2015 - Exceptionally obfuscated
author:     beta4
date:       2015-07-12 12:06:00
summary:    Hiding control flow using C++ exceptions
categories: write-ups
tags:
 - PoliCTF
 - Reversing
 - C++
 - Exceptions
 - MIPS
---

The challenge description is:

> Yet another license manager trying to protect a propietary application. The main application calls it with a challenge '84563472956326492361085746284624', the license key, and expects a response that is internally called a 'flag'. I wonder if the've implemented it securely with real crypto or it's just some crap hidden behind a bit of security through obscurity. Only one way to find out...





The file for the challenge is an .ipk package for OpenWRT (backfire) containing a MIPS binary. Note that the ipk file was recereated by hand as the build system of OpenWRT strips the binary aggressively, but stripping only makes a challenge more boring imho.

When it comes to programming, some developers like the idea of breaking complex programs in tiny, self-contained functions thinking that they can get rid of complexity in this way. However, especially if brought to the extreme, this forces who reads the code to keep a "mental call stack" to get the big picture of what is happening (so the complexity is still there!).
The core idea of this challnge was to unleash the code obfuscation potential of making very small functions, by adding a twist: hiding the control flow of an application using C++ excaptions. Beware, here we're not talking of using exceptions as a way to report erroneous conditions, but as *the only way* to return from *each and every function*. This obfuscates the call stack, as thanks to unwinding and exception type matching, a function can return an arbitrary level of function calls up in a single operation. Moreover, the way exceptions are implemented in modern C++ programs makes use of [unwind tables](http://mortoray.com/2013/09/12/the-true-cost-of-zero-cost-exceptions), so to follow the exceptions path one needs to understand those tables as well, which adds even more obfuscation.

Solution: inserting the correct key `9321430582145138541679203159315` the program would print the flag `flag{3765874926589572985013647593759}`.

The [source code](http://pastebin.com/jsMNBNSE) of the challenge.
