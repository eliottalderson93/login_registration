// //step 6 submission for Coding Dojo by Erik Nordland
// //page 16 left column then right column
// var myNumber = 42;
// var myName = "Erik Nordland";
// var temp = MyNumber;
// MyNumber = myName;
// myName = temp;
// var i =0;
// for(i = -52; i<1067; i++){
// console.log(i);
// }
// i=0;

// def beCheerful(){
// 	for(i=0; i<98; i++){
// 	console.log("good morning!");
// 	}
// 	i=0;
// }

// for(i=-300; i<1; i++){
// 	if((i%3 ==0)&&((i != -3) && (i != -6)){
// 	console.log(i);
// 	}
// }

// i = 2000;
// while(i<5281){
// console.log(i);
// i++;
// }
// i=0;

// def Birthday(given){
// 	if ((given == 0813) || (given == 1308)){
// 	console.log("How did you know?");
// 	}
// 	else{
// 	console.log("Just another day....");
// 	}
// }

// def LeapYear(year){
// 	if((year%400 == 0)){
// 	return true;
// 	}
// 	else if(year%100 == 0){
// 	return false;
// 	}
// 	else if(year%4 ==0){
// 	return true;
// 	}
// 	else{
// 	return false;
// 	}
// }

// var count = 0;
// for(i=512;i<4096;i++){
// 	if(i%5 == 0){
// 	console.log(i);
// 	count++;
// 	}
// }
// console.log(count);
// count =0;
// i=0;

// while(i<10000){
// 	console.log(6*i);
// 	i++;
// }
// i=0;

// for(i=1;i<101;i++){
// 	if(i%5 ==0){
// 	console.log("Coding")
// 		if(i%10 ==0){
// 		console.log(" Dojo")
// 		}
// 	}
// 	else{
// 	console.log(i);
// 	}
// }

// def WDYK(incoming){
// console.log(incoming);
// }
// var sum = 0;
// for(i=-300000; i<300000; i++){
// 	if (i%2 == 1){
// 	sum = sum+i;
// 	}
// }
// console.log(sum);
// i=0;
// sum=0;
// while(i<300000){
// 	if (i%2 == 1){
// 	sum = sum +i -i; 
// 	}
// }
// //The shortcut is to 
// console.log(0);
// //since each odd integer has its equal opposite in (-300000,300000). These cancel each other out.

// i=2016;
// while(i>0){
// console.log(i);
// i = i-4;
// }
// i=0;

// def FlexibleCountdown(lowNum,highNum,mult){
// 	for(i=highNum; i>lowNum; i = i-mult){
// 		console.log(i);
// 	}
// }

// def FinalCountdown(param1,param2,param3,param4){
// 	i = param2;
// 	while(i>=param3){
// 		if (i=param4){
// 		//nothing
// 		}
// 		else{
// 		console.log(i);
// 		}
// 	i = i-param1;
// 	}
// }

// //page 20
// def Countdown(number){
// 	var arr = [];
// 	for(i=number;i>=0;i--){
// 		arr.push(i);
// 	}
// 	console.log(arr.length); //this array is number+1 long
// 	return arr;
// }

// def PrintandReturn(arr){
// 	console.log(arr[0]);
// 	return arr[1];
// }

// def FirstplusLength(arr){
// 	var sum = arr[0]+arr.length;
// 	//will convert boolean to 0 or 1 or the latter integer to a string
// }

// def ValuesGreaterthanSecond(){
// 	var arr = [1,3,5,7,9,13];
// 	var count = 0;
// 	for(var k=0;k<arr.length;k++){
// 		if(arr[k]>arr[1]){
// 			console.log(arr[k]);
// 			count++;
// 		}
// 	}
// 	return count; 
// }

// def ValuesGreaterthanSecondGen(arr){
// 	var newArr = [];
// 	var count = 0;
// 	if (arr[1] != null){
// 		for(var k =0; k<arr.length;k++){
// 			if(arr[1]<arr[k]){
// 				newArr.push(arr[k]);
// 				count++;
// 			}
// 		}
// 	}
// 	else{
// 		console.log("array too short");
// 	}
// 	console.log(count);
// 	return newArr;
// }

// def LengthValue(num1,num2){
// 	var arr = [];
// 	if(num1 == num2){
// 		console.log("Jinx!");
// 	}
// 	else{
// 		for(var k =0; k<num1;k++){
// 			arr.push(num2);
// 		}
// 	}
// 	return arr;
// }

// def FittheFirst(arr){
// 	if(arr[0]>arr.length){
// 		console.log("Too big!");
// 	}
// 	else if(arr[0]<arr.length){
// 		console.log("Too small!");
// 	}
// 	else{
// 		console.log("Just right!");
// 	}
// }

// def fahrenheitToCelsius(fDegrees){
// 	var temp = 5/9*(fDegrees - 32);
// 	return temp;
// }

// def Biggie(arr){
//     for (var k = 0; k < arr.length; k++) {
//         if (arr[k] >= 0) {
//             arr[k] = "big";
//         }
//     }
//     return arr;
// }

// def PrintLowHigh(arr){
//     var max = 0;
//     var min = 100;
//     for (var k = 0; k < arr.length; k++) {
//         if (arr[k] > max) {
//             max = arr[k];
//         }
//         if (arr[k] < min) {
//             min = arr[k];
//         }
//     }
//     console.log(min);
//     return max;
// }

// def PrintOneAnother(arr){
//     var print1 = arr[arr.length - 2];
//     var odd = 0;
//     console.log(print1);
//     for (var k = 0; k < arr.length; k++) {
//         if (arr[k] % 2 != 0) {
//             odd = arr[k];
//             return odd;
//         }
//     }
// }

// def DoubleVision(arr){
//     newArr = [];
//     for (var k = 0; k < arr.length; k++) {
//         newArr.push(2 * arr[k]);
//     }
// }

// def CountPositives(arr){
//     var count = 0;
//     for (var k = 0; k < arr.length; k++) {
//         if (arr[k] > 0) {
//             count++;
//         }
//     }
//     arr[arr.length - 1] = count;
// }

// def IncrementSeconds(arr){
//     for (var k = 0; k < arr.length; k++) {
//         if (arr % 2 != 0) {
//             arr[k] = arr[k] + 1;
//         }
//         console.log(arr[k]);
//     }
//     return arr;
// }

// def PreviousLengths(arr){
//     var length = arr[arr.length-1] //first gets the last
//     for (var k = 1; k < arr.length-1; k++) {
//         arr[k] = length;
//         length = arr[k]
//     }
// }

// def AddSeven(arr){
//     var mod = arr;
//     for (var k = 1; k < arr.length; k++) {
//         mod[k] = mod[k] + 7;
//     }
//     return mod;
// }

// def ReverseArray(arr){
//     for (var k = 0; k < arr.length; k++) {
//         var l = arr.length - 1;
//         var temp = arr[l];
//         arr[l] = arr[k];
//         arr[k] = temp;
//         l--;
//     }
//     return arr;
// }


