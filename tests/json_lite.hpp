#pragma once
/* A minimal JSON reader for test vectors: objects, arrays, strings with
 * escapes, booleans, null and numbers (kept as text). Not for production. */
#include <cstring>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace test {

struct Json {
    enum Kind { Null, Bool, Num, Str, Arr, Obj } kind = Null;
    bool b = false;
    std::string s;
    std::vector<Json> arr;
    std::vector<std::pair<std::string, Json>> obj;
    const Json* get(std::string_view k) const {
        for (const auto& [key, v] : obj) if (key == k) return &v;
        return nullptr;
    }
};

struct JsonParser {
    std::string_view in;
    size_t i = 0;
    bool ok = true;
    void ws() { while (i < in.size() && std::strchr(" \t\r\n", in[i]) && in[i]) ++i; }
    bool eat(char c) { ws(); if (i < in.size() && in[i] == c) { ++i; return true; } return false; }
    static void utf8(std::string& o, unsigned cp) {
        if (cp < 0x80) { o += static_cast<char>(cp); return; }
        if (cp < 0x800) { o += static_cast<char>(0xC0 | (cp >> 6)); o += static_cast<char>(0x80 | (cp & 0x3F)); return; }
        if (cp < 0x10000) { o += static_cast<char>(0xE0 | (cp >> 12)); o += static_cast<char>(0x80 | ((cp >> 6) & 0x3F)); o += static_cast<char>(0x80 | (cp & 0x3F)); return; }
        o += static_cast<char>(0xF0 | (cp >> 18)); o += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
        o += static_cast<char>(0x80 | ((cp >> 6) & 0x3F)); o += static_cast<char>(0x80 | (cp & 0x3F));
    }
    unsigned hex4() {
        if (i + 4 > in.size()) { ok = false; return 0; }
        unsigned v = std::stoul(std::string(in.substr(i, 4)), nullptr, 16);
        i += 4;
        return v;
    }
    std::string str() {
        std::string o;
        if (!eat('"')) { ok = false; return o; }
        while (ok && i < in.size() && in[i] != '"') {
            char c = in[i++];
            if (c != '\\') { o += c; continue; }
            if (i >= in.size()) { ok = false; break; }
            const char e = in[i++];
            static constexpr const char* kEsc = "\"\\/bfnrt";
            const char* m = std::strchr(kEsc, e);
            if (e == 'u') {
                unsigned cp = hex4();
                if (cp >= 0xD800 && cp < 0xDC00 && in.substr(i, 2) == "\\u") { i += 2; cp = 0x10000 + ((cp - 0xD800) << 10) + (hex4() - 0xDC00); }
                utf8(o, cp);
                continue;
            }
            if (!m || !e) { ok = false; break; }
            o += "\"\\/\b\f\n\r\t"[m - kEsc];
        }
        if (!eat('"')) ok = false;
        return o;
    }
    Json value() {
        Json j;
        ws();
        if (i >= in.size()) { ok = false; return j; }
        const char c = in[i];
        if (c == '"') { j.kind = Json::Str; j.s = str(); return j; }
        if (c == '{') {
            ++i; j.kind = Json::Obj;
            if (eat('}')) return j;
            do { std::string k = str(); if (!eat(':')) ok = false; j.obj.emplace_back(k, value()); } while (ok && eat(','));
            if (!eat('}')) ok = false;
            return j;
        }
        if (c == '[') {
            ++i; j.kind = Json::Arr;
            if (eat(']')) return j;
            do { j.arr.push_back(value()); } while (ok && eat(','));
            if (!eat(']')) ok = false;
            return j;
        }
        if (in.substr(i, 4) == "true") { i += 4; j.kind = Json::Bool; j.b = true; return j; }
        if (in.substr(i, 5) == "false") { i += 5; j.kind = Json::Bool; return j; }
        if (in.substr(i, 4) == "null") { i += 4; return j; }
        while (i < in.size() && std::strchr("+-0123456789.eE", in[i]) && in[i]) ++i;
        j.kind = Json::Num;
        return j;
    }
};

inline std::string jstr(const Json& t, std::string_view k) {
    const Json* v = t.get(k);
    return v && v->kind == Json::Str ? v->s : std::string();
}

}
