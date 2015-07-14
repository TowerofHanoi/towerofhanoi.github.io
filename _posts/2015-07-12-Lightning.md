---
title:      PoliCTF 2015 - Lightning
author:     beta4
date:       2015-07-12 12:53:00
summary:    Reversing electronic circuits
categories: PoliCTF2015 Grabbag
tags:
 - PoliCTF
 - Grab Bag
 - Electronics
---

The challenge description is:

> You work as a security consultant, and one day a company calls you to solve a curious problem: after one night the company building was hit by a lightning, the vault could no longer be opened with the code, which is 0994. Unfortunately, the vault control hardware is inside the vault itself. You start building a breadboard prototype of the vault circuit, and after a lot of modeling and experiments, you come to the conclusion that the lightning has caused a "stuck at 1" fault on pin 14 of IC6. Based on the circuit diagram you come up with a code that could open the faulty vault. The flag is the concatenation of what appears on the display, and what you have to type in the keyboard. N.B. Flag is not in the format flag{.*} 





The files for the challenge are two images. A photo of a breadboard full of components, and a png showing the placement of the integrated circuits on the bradboard giving them component designators.
![Circuit](/img/polictf2015-lightning-circuit.jpg)
![Placement](/img/polictf2015-lightning-placement.png)

This challenge is meant to be a no-software-involved challenge where one has to reverse engineer a digital circuit. Some years ago I attended a hardware course where they told us about fault detection schemes for integrated circuits and the *stuck at* model, and that somehow came back to my mind when thinking about how to make a cool hardware challenge.

The circuit design is somewhat reminiscent of "back in the days when there were no microcontrollers", everything is done using 40xx logic series IC, asynchronous logic (where there isn't a single clock in the entire circuit), and even diode logic in some places to optimize the circuit further and use as few ICs as possible.

The main blocks of the circuit are a keypad controller whose *key pressed* output also serves as one of the clocks in the circuit advancing the display digit selector and code memory at its falling edge. The code memory is a diode ROM scanned using a 4017, and the comparison is done using a 4063, of which we will talk extensively in the following. The key comparison and display write signal is obtained with a delayed monostable from the same *key pressed* output, the delay being introduced to let the current key data bus settle. If the input key is not right, an SR flip-flop is set to indicate that at least one key is wrong. At the end of the code input sequence, further key inputs is disallowed for a short time, and if the wrong key flip-flop is not set, the led lights up signaling that the vault can open. After, the whole circuit is reset.

This circuit includes a deliberate complication and some accidental ones.

The deliberate complication is the use of a somewhat rare dot-matrix LED display, a PD2437. This display has a built-in ASCII font table, and the upper part of the data bus is hardwired to 011xxxx, thus adding 48 to the BCD data and printing numbers. However, the stuck-at causes some BCD data to be outside the 0..9 range, so that to open the vault one has to type the B key, which maps to the ASCII 0111011, which is a semicolon. However, the display type is not shown anywhere, so it has to be found on the internet. This was supposed to be easy, since it is such a distinctive display, and the feedback from the player confirmed that.

The accidental complications are two:

First, the mystery chip. The breadboard contains a surface mount ceramic package, date coded 1986, whose marking could not be found anywhere on the internet. People were supposed to guess the IC based on the operation of the rest of the circuit. This was introduced in the challenge only because I did not have a 4063 in my parts drawer, so I asked the lab assistant if he had one. We thus found an old box full of *new old stock* SMD stuff that, using the dust as a date gauge, was sitting there for quite some time. Inside we found vials with thousands of SOT23 packaged transistors and SMD capacitors, predating the time when tape and reel packaging became common for those componenets. And of course lots of 40xx logic chips, all packaged SMD and with a ceramic package with uncommon flat pins sticking out of the sides, probably military grade or something. One box had 4063 written on it, but the markings on the ICs was meaningless. As the chip worked, we thought to incldue it in the challenge as an additional complexity.

The second complication was that after building the circuit, the display woud show numbers in reverse order. This was due to the display addressing scheme. To solve this I first thought to use a 4029 presettable downcounter instead of a 4518, but it counted on the rising edge and not the falling one, so the 4518 remained. Based on the feedback from players, more than a team was stuck for this issue for a while.

Solution: Flag is `6;;22BB6`

The [schematic](/img/polictf2015-lightning-schematic.jpeg) of the challenge.
![schematic](/img/polictf2015-lightning-schematic.jpeg)
