//
// Copyright (c) 2016-2017 Konstanin Ivanov <kostyarin.ivanov@gmail.com>.
// All rights reserved. This program is free software. It comes without
// any warranty, to the extent permitted by applicable law. You can
// redistribute it and/or modify it under the terms of the Do What
// The Fuck You Want To Public License, Version 2, as published by
// Sam Hocevar. See LICENSE file for more details or see below.
//

//
//        DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
//                    Version 2, December 2004
//
// Copyright (C) 2004 Sam Hocevar <sam@hocevar.net>
//
// Everyone is permitted to copy and distribute verbatim or modified
// copies of this license document, and changing it is allowed as long
// as the name is changed.
//
//            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
//   TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION
//
//  0. You just DO WHAT THE FUCK YOU WANT TO.
//

package grokky

func must(err error) {
	if err != nil {
		panic(err)
	}
}

// Must is like Add but panics if the expression can't be parsed or
// the name is empty.
func (h Host) Must(name, expr string) {
	must(h.Add(name, expr))
}

// NewBase creates new Host that filled up with base patterns.
// To see all base patterns open 'base.go' file.
func NewBase() Host {
	h := make(Host)
	for _, v := range basePairs {
		h.Must(v.name, v.pattern)
	}
	return h
}
