/// <binding BeforeBuild='min:css' AfterBuild='min:css' Clean='clean' ProjectOpened='watch' />
"use strict";

var gulp = require("gulp"),
    rename = require('gulp-rename'),
    sass = require('gulp-sass')(require('sass')),
    postcss = require('gulp-postcss'),
    cssnano = require('cssnano'),
    autoprefixer = require('autoprefixer'),
    concat = require('gulp-concat'),
    cssmin = require("gulp-cssmin"),
    uglify = require("gulp-uglify-es").default,
    merge = require("merge-stream"),
    del = require("del"),
    bundleconfig = require("./bundleconfig.json");

var regex = {
    css: /\.css$/,
    js: /\.js$/,
    scss: /\.scss$/,
};

//gulp.task("min", ["min:js", "min:css"]);

gulp.task("min:js", function () {
    var tasks = getBundles(regex.js).map(function (bundle) {
        return gulp.src(bundle.inputFiles, { base: "." })
            .pipe(concat(bundle.outputFileName))
            .pipe(uglify())
            .pipe(gulp.dest("."));
    });
    return merge(tasks);
});

gulp.task("min:css", function () {
    var tasks = getBundles(regex.css).map(function (bundle) {
        var plugins = [
            autoprefixer(),
            cssnano()
        ];
        return gulp.src(bundle.inputFiles, { base: "." })            
            .pipe(sass())
            .pipe(postcss(plugins))
            .pipe(concat(bundle.outputFileName))
            .pipe(gulp.dest("."));
    });
    return merge(tasks);
});



gulp.task("clean", function () {
    var files = bundleconfig.map(function (bundle) {
        return bundle.outputFileName;
    });

    return del(files);
});

gulp.task("watch", function () {
    getBundles(regex.js).forEach(function (bundle) {
        gulp.watch(bundle.inputFiles, gulp.series("min:js"));
    });

    getBundles(regex.css).forEach(function (bundle) {
        gulp.watch(bundle.inputFiles, gulp.series("min:css"));
    });

});

function getBundles(regexPattern) {
    return bundleconfig.filter(function (bundle) {
        return regexPattern.test(bundle.outputFileName);
    });
}