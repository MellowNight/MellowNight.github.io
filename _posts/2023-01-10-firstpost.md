layout: post
title: "How ForteVisor works under the hood"
date: 2023-01-10 02:02:02 -0000
categories: CATEGORY-1 CATEGORY-2

## Introduction

A while ago, I wrote a type-2 AMD hypervisor with the intention of being able to dynamically analyze anti-cheats and hide the memory of internal cheats. I no longer want to treat the anti-cheat as a black box, which is why I deferred working on this project so that I can study more about devirtualization. This is by no means a very mature hypervisor with an interface to handle every guest hardware call. For larger projects and stable tool development, it's better to modify KVM and build your tools using KVM's interface. Even though KVM has its advantages, ForteVisor will always be useful for me as a library for building minimal, stealthy, dynamic analysis tools and writing hacks.

I will outline the implementation details of my AMD hypervisor, and explain some potential issues with its functionality. 

## VM setup 

## VM exit

## Sandboxing 

## Read Write logging

## Branch Tracing

## Process-specific syscall hooks

## Nested Page Table hooks
